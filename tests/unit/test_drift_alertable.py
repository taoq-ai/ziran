"""Unit tests for DriftFinding fingerprint + alertable mapping."""

from __future__ import annotations

import pytest

from ziran.domain.entities.alerting import drift_fingerprint
from ziran.domain.entities.registry import DriftFinding

pytestmark = pytest.mark.unit


def _finding(**kw: object) -> DriftFinding:
    base = {
        "server_name": "prod-mcp-server",
        "drift_type": "permission_changed",
        "severity": "high",
        "tool_name": "write_file",
        "field": "permissions",
        "previous_value": "[]",
        "current_value": "['fs:write']",
        "message": "Tool 'write_file' permissions changed on server 'prod-mcp-server'",
    }
    base.update(kw)
    return DriftFinding(**base)  # type: ignore[arg-type]


def test_fingerprint_matches_helper_and_ignores_value() -> None:
    f = _finding()
    assert f.fingerprint() == drift_fingerprint(
        "prod-mcp-server", "write_file", "permission_changed"
    )
    # Changing only the after-value must NOT change the fingerprint.
    assert f.fingerprint() == _finding(current_value="['fs:write','net']").fingerprint()


def test_fingerprint_changes_with_drift_kind() -> None:
    assert _finding().fingerprint() != _finding(drift_type="description_changed").fingerprint()


def test_to_alertable_maps_fields_and_inline_diff() -> None:
    a = _finding().to_alertable()
    assert a.kind == "registry_drift"
    assert a.severity == "high"
    assert a.fields["Server"] == "prod-mcp-server"
    assert a.fields["Tool"] == "write_file"
    # Before/after included inline (no remote snapshot URL available).
    assert a.fields["Previous"] == "[]"
    assert a.fields["Current"] == "['fs:write']"
    assert a.links == []
    assert a.fingerprint == _finding().fingerprint()
