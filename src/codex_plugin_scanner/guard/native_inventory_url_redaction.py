"""Typed client for the native inventory URL redaction; no Python composition."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeIdentity

_FEATURE = "inventory-url-redaction-v1"
_REQUEST_SCHEMA = "guard-inventory-url-redaction-request.v1"
_RESULT_SCHEMA = "guard-inventory-url-redaction-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "answers"})
_MAX_TASKS = 4096
# The resident accepts a canonical request up to 4 MiB; the wire envelope
# carries the same material plus framing, so leave room for both.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_MAX_WIRE_BYTES = 2 * _MAX_REQUEST_BYTES + 4096
# A prefetch chunk stays well inside the request budget even when every
# character of a value needs a JSON escape.
_MAX_CHUNK_TEXT_BYTES = _MAX_REQUEST_BYTES // 8
_HOST_CLASSES = frozenset({"none", "local_loopback", "local_private", "remote_public"})

_TaskKey = tuple[str, object]
# Answers already read in the current export pass, keyed by task. ``None``
# outside a pass, where every lookup is its own request.
_PASS_ANSWERS: ContextVar[dict[_TaskKey, Any] | None] = ContextVar("inventory_url_redaction_pass", default=None)


class NativeInventoryUrlRedactionError(RuntimeError):
    """The native owner could not supply a complete, request-bound redaction."""


@contextmanager
def redaction_pass() -> Iterator[None]:
    """Remember every answer read until the pass ends.

    One export repeats the same URLs across items, tools and commands; inside a
    pass each distinct value costs at most one resident answer, and ``prefetch``
    can collect them all into batched requests up front.
    """

    if _PASS_ANSWERS.get() is not None:
        yield
        return
    token = _PASS_ANSWERS.set({})
    try:
        yield
    finally:
        _PASS_ANSWERS.reset(token)


def prefetch(urls: Iterable[str], hosts: Iterable[str] = (), *, guard_home: Path | None = None) -> None:
    """Answer every URL redaction and host classification of a pass in batches.

    Outside a pass there is nowhere to keep the answers, so this does nothing.
    """

    cache = _PASS_ANSWERS.get()
    if cache is None:
        return
    tasks: list[dict[str, object]] = []
    seen: set[_TaskKey] = set()
    for kind, values in (("redact_url", urls), ("classify_endpoint_host", hosts)):
        for value in values:
            task: dict[str, object] = {"kind": kind, "value": value}
            key = _task_key(task)
            if key in cache or key in seen:
                continue
            seen.add(key)
            tasks.append(task)
    for chunk in _chunks(tasks):
        for task, answer in zip(chunk, _answers(chunk, guard_home=guard_home), strict=True):
            cache[_task_key(task)] = answer


def redact_url(value: str, *, guard_home: Path | None = None) -> str:
    """Return the exported form of one URL."""

    return _answer_for({"kind": "redact_url", "value": value}, guard_home=guard_home)


def redact_headers(header_names: list[str], *, guard_home: Path | None = None) -> dict[str, str]:
    """Return presence per header name, lowercased, in the order they were given."""

    return dict(_answer_for({"kind": "redact_headers", "header_names": header_names}, guard_home=guard_home))


def classify_endpoint_host(value: str | None, *, guard_home: Path | None = None) -> str:
    """Return where an endpoint points, decided without a network request."""

    return _answer_for({"kind": "classify_endpoint_host", "value": value}, guard_home=guard_home)


def _task_key(task: dict[str, object]) -> _TaskKey:
    kind = str(task["kind"])
    if kind == "redact_headers":
        names = task["header_names"]
        return kind, tuple(names) if isinstance(names, list) else names
    return kind, task["value"]


def _answer_for(task: dict[str, object], *, guard_home: Path | None) -> Any:
    cache = _PASS_ANSWERS.get()
    key = _task_key(task)
    if cache is not None and key in cache:
        return cache[key]
    answer = _answers([task], guard_home=guard_home)[0]
    if cache is not None:
        cache[key] = answer
    return answer


def _chunks(tasks: list[dict[str, object]]) -> Iterator[list[dict[str, object]]]:
    """Split tasks into requests that fit both the task and the size limit."""

    chunk: list[dict[str, object]] = []
    size = 0
    for task in tasks:
        value = task.get("value")
        cost = len(value.encode("utf-8")) if isinstance(value, str) else 0
        if chunk and (len(chunk) >= _MAX_TASKS or size + cost > _MAX_CHUNK_TEXT_BYTES):
            yield chunk
            chunk, size = [], 0
        chunk.append(task)
        size += cost
    if chunk:
        yield chunk


def _unusable() -> NativeInventoryUrlRedactionError:
    return NativeInventoryUrlRedactionError("native_inventory_url_redaction_invalid_result")


def _headers(answer: dict[str, Any]) -> dict[str, str]:
    """Read a header answer as the presence it reports per name."""

    pairs = answer.get("headers")
    if not isinstance(pairs, list):
        raise _unusable()
    redacted: dict[str, str] = {}
    for pair in pairs:
        if not isinstance(pair, list) or len(pair) != 2:
            raise _unusable()
        name, presence = pair
        if not isinstance(name, str) or not isinstance(presence, str):
            raise _unusable()
        redacted[name] = presence
    return redacted


def _text(answer: dict[str, Any], field: str) -> str:
    """Read the one string a non-header answer carries."""

    value = answer.get(field)
    if not isinstance(value, str):
        raise _unusable()
    return value


def _answer(answer: object, task: dict[str, object]) -> Any:
    """Read the answer the resident gave for this task, or refuse the reply.

    The shape is checked before the reply counts as usable, so an answer the
    caller cannot read records the resident as failing rather than succeeding.
    """

    kind = task["kind"]
    if not isinstance(answer, dict) or answer.get("kind") != kind:
        raise _unusable()
    if kind == "redact_headers":
        return _headers(answer)
    if kind == "redact_url":
        return _text(answer, "value")
    host_class = _text(answer, "host_class")
    # A class outside the contract would read as a safe endpoint downstream.
    if host_class not in _HOST_CLASSES:
        raise _unusable()
    return host_class


def _answers(
    tasks: list[dict[str, object]],
    *,
    guard_home: Path | None,
    timeout_seconds: float = 10.0,
) -> list[Any]:
    """Ask the resident for one redaction pass and verify it answers this request.

    The redaction is what keeps an operator's credentials and private hosts out
    of an exported inventory, so it has exactly one composition and the resident
    owns it. Every outcome other than a well-formed, request-bound ``ok`` reply
    raises ``NativeInventoryUrlRedactionError``; a caller must not fall back to
    a local redaction, which would be a second place an export can be declared
    safe.
    """

    if len(tasks) > _MAX_TASKS:
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_invalid")
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("inventory_url_redaction"),
        "tasks": tasks,
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
        # The resident answers with the prefixed token, so bind against the same form.
        request_sha256 = "sha256:" + _canonical_request_sha256(wire)
        # Resolved once: the transport and the health record below must name
        # the same binary, and the lookup walks the runtime on disk.
        status = native_runtime_status()
        decoded = native_execution._resident_request(
            operation="inventory_url_redaction",
            request=wire,
            guard_home=home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
            # Success is recorded below, once the reply is known to be usable.
            record_success=False,
            status=status,
        )
    except NativeInventoryUrlRedactionError:
        raise
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        # A home that cannot be resolved raises a plain RuntimeError.
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable") from error
    if decoded is None:
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
    try:
        answers = _validated_answers(decoded, wire, request_sha256, tasks)
    except NativeInventoryUrlRedactionError:
        _record(home, status.identity, success=False)
        raise
    _record(home, status.identity, success=True)
    return answers


def _validated_answers(
    decoded: dict[str, Any],
    wire: dict[str, object],
    request_sha256: str,
    tasks: list[dict[str, object]],
) -> list[Any]:
    if set(decoded) != _RESULT_KEYS or decoded.get("code") != "ok" or decoded.get("status") != "ok":
        raise _unusable()
    if decoded.get("request_id") != wire["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_request_mismatch")
    answers: Any = decoded.get("answers")
    # One answer per task, or the caller cannot tell which string it holds.
    if not isinstance(answers, list) or len(answers) != len(tasks):
        raise _unusable()
    return [_answer(answer, task) for answer, task in zip(answers, tasks, strict=True)]


def _record(home: Path, identity: NativeRuntimeIdentity | None, *, success: bool) -> None:
    if identity is None:
        return
    if success:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason="native_inventory_url_redaction_result")
