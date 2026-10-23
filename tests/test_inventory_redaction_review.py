"""Regression coverage for nested sensitive metadata in the serializer."""

from __future__ import annotations

import copy
import json

import pytest

from codex_plugin_scanner.guard.inventory_contract_redaction import _safe_json


@pytest.mark.security_critical
@pytest.mark.parametrize("sensitive_parent", [False, True])
def test_nested_sensitive_metadata_keeps_all_sibling_keys(sensitive_parent: bool) -> None:
    """Keep every nested field while redacting its sensitive values without modifying the input."""
    source = {
        "tokenInfo": {
            "primary": {"value": "first-private-value", "note": "first-private-note"},
            "secondary": {"value": "second-private-value", "note": "second-private-note"},
            "history": [{"left": "third-private-value", "right": "fourth-private-value"}],
        }
    }
    original = copy.deepcopy(source)
    result = _safe_json(source, parent_sensitive=sensitive_parent)
    assert result == {
        "tokenInfo": {
            "primary": {"value": "[REDACTED]", "note": "[REDACTED]"},
            "secondary": {"value": "[REDACTED]", "note": "[REDACTED]"},
            "history": [{"left": "[REDACTED]", "right": "[REDACTED]"}],
        }
    }
    assert source == original
    assert "private-value" not in json.dumps(result)
    assert "private-note" not in json.dumps(result)


def test_sensitive_ancestor_does_not_disable_unsafe_key_redaction() -> None:
    """Preserve structural names, not literal secrets embedded in a key itself."""
    result = _safe_json({"safeField": "private-value", "sk-secret-key": "another-private-value"}, parent_sensitive=True)
    assert result == {"safeField": "[REDACTED]", "[REDACTED]": "[REDACTED]"}
