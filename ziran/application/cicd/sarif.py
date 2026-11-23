"""SARIF v2.1.0 report generator.

Converts ZIRAN scan results into the `Static Analysis Results
Interchange Format <https://docs.oasis-open.org/sarif/sarif/v2.1.0/>`_
so GitHub Code Scanning, Azure DevOps, and other platforms can
display findings natively.

Usage::

    from ziran.application.cicd.sarif import generate_sarif
    sarif = generate_sarif(campaign_result)
    Path("results.sarif").write_text(json.dumps(sarif, indent=2))
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ziran.application.knowledge_graph.chain_analyzer import CHAIN_RULE_ID
from ziran.application.knowledge_graph.trifecta import DELEGATED_RULE_ID as LT002
from ziran.application.knowledge_graph.trifecta import DELEGATED_TYPE, LEGS
from ziran.application.knowledge_graph.trifecta import RULE_ID as LT001
from ziran.application.knowledge_graph.trifecta import VULNERABILITY_TYPE as TRIFECTA
from ziran.domain.entities.attack import (
    OWASP_LLM_DESCRIPTIONS,
    OwaspLlmCategory,
)
from ziran.domain.entities.capability import BlastRadius

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ziran.application.static_analysis.analyzer import StaticFinding
    from ziran.domain.entities.ci import GateResult
    from ziran.domain.entities.phase import CampaignResult

_SEVERITY_TO_SARIF: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_SECURITY_SEVERITY: dict[str, str] = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "3.0",
}

_SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_ZIRAN_VERSION = "0.1.0"

_TRIFECTA_RULES: dict[str, str] = {TRIFECTA: LT001, DELEGATED_TYPE: LT002}


def generate_sarif(result: CampaignResult, gate: GateResult | None = None) -> dict[str, Any]:
    """Generate a SARIF v2.1.0 document from a campaign result.

    Args:
        result: The campaign result to convert.
        gate: Optional gate outcome; its suppressed attack results are marked
            with an external SARIF ``suppressions`` entry.

    Returns:
        A dictionary conforming to the SARIF v2.1.0 JSON schema,
        ready to be serialised with :func:`json.dumps`.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()
    suppressed = gate.suppressed_attacks() if gate else {}

    for i, raw in enumerate(result.attack_results):
        ar: dict[str, Any] = raw if isinstance(raw, dict) else raw.model_dump()
        if not ar.get("successful"):
            continue

        vector_id = ar.get("vector_id", "unknown")
        vector_name = ar.get("vector_name", vector_id)
        severity: str = ar.get("severity", "medium")
        category: str = ar.get("category", "unknown")
        owasp: list[str] = ar.get("owasp_mapping", [])

        # Register rule (deduplicated)
        if vector_id not in seen_rule_ids:
            seen_rule_ids.add(vector_id)
            rule = _build_rule(vector_id, vector_name, severity, category, owasp)
            rules.append(rule)

        # Add result
        sarif_result = _build_result(ar, vector_id, severity)
        if i in suppressed:
            sarif_result["suppressions"] = [{"kind": "external", "justification": suppressed[i]}]
        results.append(sarif_result)

    suppressed_chains = gate.suppressed_chains() if gate else {}
    chain_rules: dict[str, dict[str, Any]] = {}
    for i, chain in enumerate(result.dangerous_tool_chains):
        tools = chain.get("tools") or []
        radius = result.blast_radius.get(str(tools[-1])) if tools else None
        chain_result = _chain_result(chain, chain_rules, radius)
        if i in suppressed_chains:
            chain_result["suppressions"] = [
                {"kind": "external", "justification": suppressed_chains[i]}
            ]
        results.append(chain_result)
    rules.extend(chain_rules.values())

    return _sarif_document(rules, results)


def _chain_result(
    chain: dict[str, Any], rules: dict[str, dict[str, Any]], radius: dict[str, Any] | None = None
) -> dict[str, Any]:
    """One SARIF result for a dangerous chain; registers (or raises) its rule in *rules*.

    ``LT001`` and ``LT002`` take the two trifecta types; every other type shares ``CC001``, the
    audit's chain rule, with the type in ``properties.vulnerability_type`` (spec 092). *radius*,
    the chain's last tool's entry in ``CampaignResult.blast_radius``, adds a fixed-size summary
    in ``properties.blast_radius`` (spec 091).
    """
    vt: str = chain.get("vulnerability_type", "unknown")
    tools = [str(t) for t in chain.get("tools", [])]
    risk: str = chain.get("risk_level", "medium")
    if risk not in _SEVERITY_RANK:
        risk = "medium"
    evidence: dict[str, Any] = chain.get("evidence") or {}
    rule_id = _TRIFECTA_RULES.get(vt, CHAIN_RULE_ID)
    if rule_id == CHAIN_RULE_ID:
        text = f"{vt}: {' -> '.join(tools)}"
        rule = rules.setdefault(rule_id, _chain_rule())
        if float(_SECURITY_SEVERITY[risk]) > float(rule["properties"]["security-severity"]):
            rule["defaultConfiguration"]["level"] = _SEVERITY_TO_SARIF[risk]
            rule["properties"]["security-severity"] = _SECURITY_SEVERITY[risk]
    else:
        text = f"{vt}: " + "; ".join(
            f"{leg} from {', '.join(map(str, evidence.get(leg, [])))}" for leg in LEGS
        )
        rules.setdefault(rule_id, _trifecta_rule(rule_id, vt))
    properties: dict[str, Any] = {"tools": tools, "vulnerability_type": vt}
    for key in ("agent", "agents"):
        if key in evidence:
            properties[key] = evidence[key]
    if radius is not None:
        parts = BlastRadius.model_validate(radius)
        both = (parts.demonstrated, parts.reachable)
        properties["blast_radius"] = {
            "demonstrated": parts.demonstrated.counts,
            "reachable": parts.reachable.counts,
            "external": any(p.external for p in both),
            "data_classes": sorted({t.data_class for p in both for t in p.tags.values()}),
        }
    # code scanning merges results of one rule at one location unless their fingerprints differ;
    # tools keep their order: a chain is a path, so a -> b and b -> a are two chains
    key = json.dumps([vt, evidence.get("agent"), tools], default=str)
    return {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_SARIF[risk],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "agent-under-test", "uriBaseId": "%SRCROOT%"}
                }
            }
        ],
        "partialFingerprints": {"ziranChain/v1": hashlib.sha256(key.encode()).hexdigest()},
        "properties": properties,
    }


def _chain_rule() -> dict[str, Any]:
    """The shared ``CC001`` rule; ``_chain_result`` raises it to the highest risk seen."""
    return {
        "id": CHAIN_RULE_ID,
        "name": "dangerous_tool_chain",
        "shortDescription": {"text": "dangerous_tool_chain"},
        "fullDescription": {
            "text": "The agent's tools combine into a dangerous chain; "
            "properties.vulnerability_type names it"
        },
        "help": {"text": "Remove one tool of the chain from the agent, or split the agent."},
        "defaultConfiguration": {"level": "note"},
        "properties": {"tags": ["tool_composition"], "security-severity": "3.0"},
    }


def _trifecta_rule(rule_id: str = LT001, name: str = TRIFECTA) -> dict[str, Any]:
    """The LT001 rule, shared with ``ziran audit`` (spec 088), or the delegated LT002."""
    text = (
        "An agent and the agents it delegates to read private data, see untrusted content and "
        "can send data out"
        if rule_id == LT002
        else "One agent reads private data, sees untrusted content and can send data out"
    )
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": text},
        "help": {"text": "Remove or restrict one leg of the trifecta."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["tool_composition"], "security-severity": "9.0"},
    }


def generate_audit_sarif(findings: Sequence[StaticFinding]) -> dict[str, Any]:
    """Generate a SARIF v2.1.0 document for ``ziran audit`` rows.

    One result per finding in report order; one rule per distinct
    ``check_id`` (first-seen order) carrying the highest severity seen.
    ``StaticFinding.context`` is never read.
    """
    rules: dict[str, dict[str, Any]] = {}
    top: dict[str, str] = {}
    results: list[dict[str, Any]] = []
    cwd = Path.cwd()

    for f in findings:
        rule = rules.setdefault(
            f.check_id, {"id": f.check_id, "shortDescription": {"text": f.check_id}}
        )
        if f.recommendation and "help" not in rule:
            rule["help"] = {"text": f.recommendation}
        if _SEVERITY_RANK[f.severity] >= _SEVERITY_RANK[top.get(f.check_id, "low")]:
            top[f.check_id] = f.severity

        p = Path(f.file_path)
        if p.is_absolute() and p.is_relative_to(cwd):
            p = p.relative_to(cwd)
        artifact = (
            {"uri": p.as_uri()}
            if p.is_absolute()
            else {"uri": p.as_posix(), "uriBaseId": "%SRCROOT%"}
        )
        physical: dict[str, Any] = {"artifactLocation": artifact}
        if f.line_number:
            physical["region"] = {"startLine": f.line_number}
        result: dict[str, Any] = {
            "ruleId": f.check_id,
            "level": _SEVERITY_TO_SARIF[f.severity],
            "message": {"text": f.message},
            "locations": [{"physicalLocation": physical}],
        }
        if f.agent is not None:
            result["properties"] = {"agent": f.agent, "tools": list(f.tools)}
        results.append(result)

    for check_id, rule in rules.items():
        rule["defaultConfiguration"] = {"level": _SEVERITY_TO_SARIF[top[check_id]]}
        rule["properties"] = {"security-severity": _SECURITY_SEVERITY[top[check_id]]}
    return _sarif_document(list(rules.values()), results)


def _sarif_document(rules: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap *rules* and *results* in the ZIRAN SARIF v2.1.0 envelope."""
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ZIRAN",
                        "version": _ZIRAN_VERSION,
                        "informationUri": "https://github.com/taoq-ai/ziran",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(result: CampaignResult, path: Path, gate: GateResult | None = None) -> Path:
    """Generate SARIF and write it to *path*.

    Returns:
        The path that was written.
    """
    sarif = generate_sarif(result, gate)
    path.write_text(json.dumps(sarif, indent=2))
    return path


# ── Internal builders ────────────────────────────────────────────────


def _build_rule(
    vector_id: str,
    name: str,
    severity: str,
    category: str,
    owasp: list[str],
) -> dict[str, Any]:
    """Create a SARIF ``reportingDescriptor`` (rule)."""
    help_text = f"Category: {category.replace('_', ' ').title()}"
    if owasp:
        owasp_text = ", ".join(
            f"{o}: {OWASP_LLM_DESCRIPTIONS.get(OwaspLlmCategory(o), o)}" for o in owasp
        )
        help_text += f" | OWASP: {owasp_text}"

    rule: dict[str, Any] = {
        "id": vector_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": help_text},
        "defaultConfiguration": {
            "level": _SEVERITY_TO_SARIF.get(severity, "warning"),
        },
        "properties": {
            "tags": [category, *(f"owasp/{o}" for o in owasp)],
        },
    }
    return rule


def _build_result(
    ar: dict[str, Any],
    rule_id: str,
    severity: str,
) -> dict[str, Any]:
    """Create a SARIF ``result`` from an attack result dict."""
    message_parts = []
    if ar.get("agent_response"):
        response_preview = ar["agent_response"][:200]
        message_parts.append(f"Agent response: {response_preview}")
    if ar.get("prompt_used"):
        message_parts.append(f"Prompt: {ar['prompt_used'][:200]}")

    message_text = " | ".join(message_parts) if message_parts else f"Attack {rule_id} succeeded"

    sarif_result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_SARIF.get(severity, "warning"),
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "agent-under-test",
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
        ],
    }

    # Attach evidence as properties
    evidence = ar.get("evidence", {})
    if evidence:
        sarif_result["properties"] = {"evidence": evidence}

    return sarif_result
