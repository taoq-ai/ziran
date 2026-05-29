"""Unit tests for trace dangerous-chain → alertable mapping + digest."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ziran.application.trace_analysis.alerting import (
    build_digest,
    chain_to_alertable,
    match_predeploy,
)
from ziran.domain.entities.alerting import trace_fingerprint
from ziran.domain.entities.capability import DangerousChain
from ziran.domain.entities.trace import TraceSession

pytestmark = pytest.mark.unit


def _chain(tools: list[str] | None = None, **kw: object) -> DangerousChain:
    base: dict[str, object] = {
        "tools": tools or ["read_file", "http_request"],
        "risk_level": "high",
        "vulnerability_type": "data_exfiltration",
        "exploit_description": "read then exfiltrate",
        "remediation": "deny http_request after read_file",
        "occurrence_count": 2,
    }
    base.update(kw)
    return DangerousChain(**base)  # type: ignore[arg-type]


def _session(session_id: str = "sess-1", **kw: object) -> TraceSession:
    ts = datetime(2026, 5, 29, tzinfo=UTC)
    base: dict[str, object] = {
        "session_id": session_id,
        "tool_calls": [],
        "start_time": ts,
        "end_time": ts,
        "source": "langfuse",
    }
    base.update(kw)
    return TraceSession(**base)  # type: ignore[arg-type]


def test_fingerprint_combines_chain_and_session() -> None:
    a = chain_to_alertable(_chain(), _session("sess-1"))
    assert a.fingerprint == trace_fingerprint("read_file->http_request", "sess-1")
    # Same chain, different session → different fingerprint.
    b = chain_to_alertable(_chain(), _session("sess-2"))
    assert a.fingerprint != b.fingerprint


def test_mapping_includes_required_context() -> None:
    a = chain_to_alertable(_chain(), _session("sess-1", metadata={"trace_url": "https://lf/t/1"}))
    assert a.kind == "dangerous_chain"
    assert a.severity == "high"
    assert a.fields["Tool sequence"] == "read_file → http_request"
    assert a.fields["Session"] == "sess-1"
    assert a.fields["Trace source"] == "langfuse"
    assert a.remediation == "deny http_request after read_file"
    assert a.links[0].url == "https://lf/t/1"


def test_matched_predeploy_inherits_severity_and_remediation() -> None:
    predeploy = [
        {
            "tools": ["read_file", "http_request"],
            "risk_level": "critical",
            "remediation": "block it",
        }
    ]
    chain = _chain(risk_level="medium")
    matched = match_predeploy(chain, predeploy)
    assert matched is not None
    a = chain_to_alertable(chain, _session(), matched=matched, predeploy_ref="scan.json")
    assert a.severity == "critical"  # inherited from pre-deploy finding
    assert a.remediation == "block it"
    assert a.fields["Matched pre-deploy finding"] == "scan.json"


def test_no_match_returns_none() -> None:
    assert match_predeploy(_chain(["a", "b"]), [{"tools": ["x", "y"]}]) is None


def test_digest_aggregates_and_takes_top_severity() -> None:
    findings = [
        chain_to_alertable(_chain(risk_level="medium"), _session("s1")),
        chain_to_alertable(_chain(["sql", "exec"], risk_level="critical"), _session("s2")),
    ]
    digest = build_digest(findings)
    assert digest.severity == "critical"
    assert "2 dangerous chain" in digest.title
    # Digest fingerprint is independent of ordering.
    assert build_digest(findings).fingerprint == build_digest(list(reversed(findings))).fingerprint
