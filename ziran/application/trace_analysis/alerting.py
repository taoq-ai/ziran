"""Map production dangerous-chain matches to alertable findings."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ziran.domain.entities.alerting import (
    AlertableFinding,
    AlertLink,
    digest_fingerprint,
    severity_rank,
    trace_fingerprint,
)

if TYPE_CHECKING:
    from ziran.domain.entities.attack import Severity
    from ziran.domain.entities.capability import DangerousChain
    from ziran.domain.entities.trace import TraceSession

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _to_severity(risk_level: str) -> Severity:
    """Coerce a chain risk level to a canonical severity (default ``medium``)."""
    value = risk_level.lower().strip()
    if value in _VALID_SEVERITIES:
        return value  # type: ignore[return-value]
    return "medium"


def _tool_chain_hash(chain: DangerousChain) -> str:
    return "->".join(chain.tools)


def match_predeploy(
    chain: DangerousChain,
    predeploy_chains: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Find a pre-deploy finding whose tool sequence matches this chain."""
    target = list(chain.tools)
    for candidate in predeploy_chains:
        if list(candidate.get("tools", [])) == target:
            return candidate
    return None


def chain_to_alertable(
    chain: DangerousChain,
    session: TraceSession,
    *,
    matched: dict[str, Any] | None = None,
    predeploy_ref: str | None = None,
) -> AlertableFinding:
    """Map a dangerous chain observed in *session* to an alertable finding.

    When *matched* (a pre-deploy finding) is supplied, severity and remediation
    are inherited from it and a link to the pre-deploy finding is attached.
    """
    severity = (
        _to_severity(str(matched["risk_level"])) if matched else _to_severity(chain.risk_level)
    )
    remediation = (matched.get("remediation") if matched else None) or chain.remediation or None

    fields: dict[str, str] = {
        "Tool sequence": " → ".join(chain.tools),
        "Vulnerability type": chain.vulnerability_type,
        "Session": session.session_id,
        "Trace source": session.source,
        "Occurrences": str(chain.occurrence_count),
    }
    if matched:
        fields["Matched pre-deploy finding"] = predeploy_ref or "yes"

    links: list[AlertLink] = []
    trace_url = session.metadata.get("trace_url")
    if isinstance(trace_url, str) and trace_url:
        links.append(AlertLink(label=f"Trace ({session.source})", url=trace_url))

    return AlertableFinding(
        fingerprint=trace_fingerprint(_tool_chain_hash(chain), session.session_id),
        kind="dangerous_chain",
        severity=severity,
        title=f"{chain.vulnerability_type} chain observed in production ({session.session_id})",
        summary=chain.exploit_description,
        fields=fields,
        links=links,
        remediation=remediation,
    )


def build_digest(findings: list[AlertableFinding]) -> AlertableFinding:
    """Aggregate per-session findings into a single digest finding.

    The digest fingerprint is derived solely from the contained chain
    fingerprints (no run date), so re-running on unchanged traces reuses the
    same digest issue.
    """
    fingerprints = [f.fingerprint for f in findings]
    top_severity: Severity = "low"
    for finding in findings:
        if severity_rank(finding.severity) > severity_rank(top_severity):
            top_severity = finding.severity

    lines = [f"- {f.title}" for f in findings]
    return AlertableFinding(
        fingerprint=digest_fingerprint(fingerprints),
        kind="dangerous_chain",
        severity=top_severity,
        title=f"Trace analysis digest: {len(findings)} dangerous chain execution(s)",
        summary="Multiple dangerous tool-chain executions were observed in production traces.",
        fields={"Chains": "\n".join(lines)},
    )
