"""Guard CLI helper definitions."""

# pyright: reportImportCycles=false

# ruff: noqa: F403, F405

from __future__ import annotations

from ..native_codex_tool_output import codex_tool_output_native
from ..native_prompt import artifact_from_dict
from ..native_sensitive_request import NativeSensitiveRequestError
from ._commands_shared import *
from .commands_parser_helpers import *

_CODEX_TOOL_RESPONSE_MAX_DEPTH = 5


_CODEX_TOOL_RESPONSE_TEXT_LIMIT = 5 * 1024 * 1024


_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH = 24


def _redact_codex_prompt_secret_assignments(value: str) -> str:
    """Resolve redaction lazily so Codex output handling has no import-order gap."""

    from .commands_support_runtime_resolution import _redact_codex_prompt_secret_assignments as resolve

    return resolve(value)


def _truncate_codex_display_text(value: str, *, limit: int) -> str:
    """Resolve display truncation lazily so output inspection remains available at startup."""

    from .commands_support_runtime_resolution import _truncate_codex_display_text as resolve

    return resolve(value, limit=limit)


def _path_contains_symlink(path: Path, *, base_dir: Path) -> bool:
    from ..runtime.source_paths import path_contains_symlink

    return path_contains_symlink(path, base_dir=base_dir)


def _collect_codex_tool_response_text(value: object, *, depth: int = 0) -> str:
    if depth > _CODEX_TOOL_RESPONSE_MAX_DEPTH:
        return ""
    if isinstance(value, str):
        return value[:_CODEX_TOOL_RESPONSE_TEXT_LIMIT]
    if isinstance(value, dict):
        parts: list[str] = []
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in {"stdout", "stderr", "output", "text", "content", "result", "message"} or depth > 0:
                text = _collect_codex_tool_response_text(child, depth=depth + 1)
                if text:
                    parts.append(text)
        return "\n".join(parts)[:_CODEX_TOOL_RESPONSE_TEXT_LIMIT]
    if isinstance(value, list):
        return "\n".join(_collect_codex_tool_response_text(item, depth=depth + 1) for item in value)[
            :_CODEX_TOOL_RESPONSE_TEXT_LIMIT
        ]
    return ""


_PROMPT_PATH_TOKEN_PATTERN = re.compile(
    r"(?<![\w/.-])\.[A-Za-z0-9][A-Za-z0-9_.-]{0,255}|"
    r"(?:~|\.{1,2}|/)[^\s'\"`<>|;(){}\[\]]{0,255}"
)


_PROMPT_FILE_READ_VERB_PATTERN = re.compile(r"\b(?:read|open|print|show|dump|cat|head|tail|less|view|display)\b", re.I)


_CODEX_PROMPT_RETRY_BOILERPLATE_PATTERNS = (
    re.compile(
        r"Warning:\s*HOL Guard flagged this prompt because it asks for direct local secret access and is protecting "
        r"your local secrets\. If that is intentional, continue and Guard will ask again on the actual tool call\. "
        r"Open HOL Guard to approve or keep this blocked:\s*\S+\. "
        r"After you choose, retry the same the harness action\.?",
        re.IGNORECASE,
    ),
    re.compile(
        r"HOL Guard stopped this Codex prompt before Codex could open (?:a credential-looking local file|a sensitive "
        r"local file)\. Codex does not expose native approval prompts for Read-tool file reads, so Guard blocks this "
        r"request at prompt time\. Open HOL Guard to approve or keep this blocked:\s*\S+\. After you choose, retry "
        r"the same Codex action\.?",
        re.IGNORECASE,
    ),
)


def _codex_prompt_credential_file_artifact(
    *,
    prompt_text: str,
    cwd: Path | None,
    config_path: str,
) -> GuardArtifact | None:
    """Review the prompt in the resident: the artifact it names, or ``None``."""

    answer = codex_tool_output_native(
        "prompt_credential_file",
        prompt_text=prompt_text,
        cwd=cwd,
        config_path=config_path,
        deadline_ms=8_000,
        timeout_seconds=9.0,
    )
    if not answer.allowed or answer.value is None or answer.error_code is not None:
        raise NativeSensitiveRequestError(answer.error_code or "native_codex_prompt_file_unavailable")
    return artifact_from_dict(json.loads(answer.value))


def _with_codex_prompt_display_metadata(artifact: GuardArtifact, *, prompt_text: str) -> GuardArtifact:
    matched_text = artifact.metadata.get("prompt_matched_text")
    display = _codex_prompt_display_text(
        prompt_text,
        requested_path=matched_text if isinstance(matched_text, str) else None,
    )
    metadata = {
        **artifact.metadata,
        "prompt_display_text": display,
        "request_summary": display,
        "runtime_request_summary": display,
    }
    return replace(artifact, metadata=metadata)


def _codex_prompt_display_text(prompt_text: str, *, requested_path: str | None = None) -> str:
    sanitized_prompt = _sanitize_codex_display_text(prompt_text)
    path_suffix = ""
    if requested_path is not None and requested_path.strip():
        path_suffix = f" for `{_sanitize_codex_display_text(requested_path.strip())}`"
    return f"Codex prompt{path_suffix}: {_truncate_codex_display_text(sanitized_prompt, limit=320)}"


def _codex_prompt_intent_text(prompt_text: str) -> str:
    normalized = _sanitize_codex_display_text(prompt_text)
    for pattern in _CODEX_PROMPT_RETRY_BOILERPLATE_PATTERNS:
        normalized = pattern.sub(" ", normalized)
    return " ".join(normalized.split())


def _sanitize_codex_display_text(value: str) -> str:
    collapsed = " ".join(value.strip().split())
    redacted = _redact_codex_prompt_secret_assignments(collapsed)
    sanitized = re.sub(r"/(?:Users|home)/[^/\s]+", "~", redacted)
    return re.sub(r"[A-Za-z]:\\Users\\[^\\\s]+", "~", sanitized)


__all__ = [
    "_PROMPT_FILE_READ_VERB_PATTERN",
    "_PROMPT_PATH_TOKEN_PATTERN",
    "_codex_prompt_credential_file_artifact",
    "_codex_prompt_display_text",
    "_collect_codex_tool_response_text",
    "_path_contains_symlink",
    "_sanitize_codex_display_text",
    "_with_codex_prompt_display_metadata",
]
