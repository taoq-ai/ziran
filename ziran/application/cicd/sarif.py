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

from ziran import __version__
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
from ziran.domain.entities.phase import (
    UNMEASURED_METADATA_KEY,
    WARNINGS_METADATA_KEY,
    CampaignResult,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ziran.application.static_analysis.analyzer import StaticFinding
    from ziran.domain.entities.ci import GateResult

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


_TRIFECTA_RULES: dict[str, str] = {TRIFECTA: LT001, DELEGATED_TYPE: LT002}


#: SARIF level of a vector with signals and no evidence: shown, below every finding.
_REVIEW_LEVEL = "note"


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
        review = not ar.get("successful") and bool((ar.get("evidence") or {}).get("needs_review"))
        if not ar.get("successful") and not review:
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
            if review:
                rule["defaultConfiguration"]["level"] = _REVIEW_LEVEL
            rules.append(rule)

        # Add result
        sarif_result = _build_result(ar, vector_id, severity)
        if review:  # signals with no evidence (study-v2.1): visible in CI, never a finding
            signals = list(ar["evidence"].get("signals", []))
            sarif_result["level"] = _REVIEW_LEVEL
            sarif_result["message"]["text"] = (
                f"Signals to review, not a finding ({', '.join(signals) or 'judge'}): "
                f"no evidence that attack {vector_id} succeeded"
            )
            sarif_result["properties"] |= {"needs_review": True, "signals": signals}
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

    return _sarif_document(rules, results, {"ziran": _gate_inputs(result)})


def _phase_vulnerabilities(result: CampaignResult) -> dict[str, list[str]]:
    """Phase to its vulnerability ids, merged when a phase repeats."""
    merged: dict[str, list[str]] = {}
    for p in result.phases_with_findings:
        merged.setdefault(str(p.phase), []).extend(p.vulnerabilities_found)
    return merged


def _gate_inputs(result: CampaignResult) -> dict[str, Any]:
    """The campaign fields ``QualityGate`` reads beyond the results (spec 093 FR-001)."""
    keys = (UNMEASURED_METADATA_KEY, WARNINGS_METADATA_KEY)
    return {
        "schema": _GATE_SCHEMA,
        "attack_count": len(result.attack_results),
        "campaign_id": result.campaign_id,
        "target_agent": result.target_agent,
        "final_trust_score": result.final_trust_score,
        "success": result.success,
        "critical_paths": result.critical_paths,
        "phase_vulnerabilities": _phase_vulnerabilities(result),
        "metadata": {k: result.metadata[k] for k in keys if k in result.metadata},
    }


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
    properties: dict[str, Any] = {
        "tools": tools,
        "vulnerability_type": vt,
        "severity": chain.get("risk_level", "medium"),
    }
    if chain.get("graph_path"):
        properties["graph_path"] = chain["graph_path"]
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
        if f.atlas:
            result.setdefault("properties", {})["atlas"] = list(f.atlas)
        results.append(result)

    for check_id, rule in rules.items():
        rule["defaultConfiguration"] = {"level": _SEVERITY_TO_SARIF[top[check_id]]}
        rule["properties"] = {"security-severity": _SECURITY_SEVERITY[top[check_id]]}
    return _sarif_document(list(rules.values()), results)


def _sarif_document(
    rules: list[dict[str, Any]],
    results: list[dict[str, Any]],
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Wrap *rules* and *results* (and run *properties*) in the ZIRAN SARIF v2.1.0 envelope."""
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "ZIRAN",
                "version": __version__,
                "informationUri": "https://github.com/taoq-ai/ziran",
                "rules": rules,
            }
        },
        "results": results,
    }
    if properties is not None:
        run["properties"] = properties
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
        "version": "2.1.0",
        "runs": [run],
    }


def write_sarif(result: CampaignResult, path: Path, gate: GateResult | None = None) -> Path:
    """Generate SARIF and write it to *path*.

    Returns:
        The path that was written.
    """
    sarif = generate_sarif(result, gate)
    path.write_text(json.dumps(sarif, indent=2))
    return path


_GATE_SCHEMA = 1
_MAX_ATTACK_COUNT = 1_000_000  # a crafted count cannot pad the result past this
_REQUIRED_GATE_INPUTS = ("target_agent", "final_trust_score", "success", "attack_count")


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        msg = f"SARIF {where} must be an object, got {type(value).__name__}"
        raise ValueError(msg)
    return value


def _array(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        msg = f"SARIF {where} must be an array, got {type(value).__name__}"
        raise ValueError(msg)
    return value


def campaign_from_sarif(doc: Any) -> CampaignResult:
    """Rebuild the gate's view of a campaign from a SARIF ``generate_sarif`` wrote (spec 093).

    Attacks and chains come back in result order with the fields ``QualityGate`` reads; the
    trust score, verdict, critical paths and phase findings come from
    ``runs[0].properties.ziran``.

    Raises:
        ValueError: not one run, a malformed shape, or missing ziran run properties (named).
    """
    runs = _array(_mapping(doc, "log").get("runs"), "runs")
    if len(runs) != 1:
        msg = f"expected one SARIF run as ziran writes, got {len(runs)}"
        raise ValueError(msg)
    run = _mapping(runs[0], "runs[0]")
    run_props = _mapping(run.get("properties", {}), "runs[0].properties")
    gate_inputs = _mapping(run_props.get("ziran", {}), "runs[0].properties.ziran")
    missing = [k for k in _REQUIRED_GATE_INPUTS if k not in gate_inputs]
    if missing:
        msg = (
            f"not a ziran scan SARIF: runs[0].properties.ziran lacks {', '.join(missing)}; "
            "write it with `ziran ci --sarif` from a scan result"
        )
        raise ValueError(msg)
    if gate_inputs.get("schema", _GATE_SCHEMA) != _GATE_SCHEMA:
        msg = f"unsupported ziran SARIF schema {gate_inputs['schema']}; this ziran reads 1"
        raise ValueError(msg)

    driver = _mapping(_mapping(run.get("tool", {}), "tool").get("driver", {}), "tool.driver")
    rules: dict[str, dict[str, Any]] = {}
    for i, raw_rule in enumerate(_array(driver.get("rules", []), "tool.driver.rules")):
        rule = _mapping(raw_rule, f"rules[{i}]")
        rules[str(rule.get("id"))] = rule

    attacks: list[dict[str, Any]] = []
    chains: list[dict[str, Any]] = []
    for i, raw in enumerate(_array(run.get("results", []), "results")):
        row = _mapping(raw, f"results[{i}]")
        if "ruleId" not in row:
            msg = f"SARIF results[{i}] has no ruleId"
            raise ValueError(msg)
        props = _mapping(row.get("properties", {}), f"results[{i}].properties")
        severity = props.get("severity", "medium")
        if "vulnerability_type" in props:
            chain = {
                "vulnerability_type": props["vulnerability_type"],
                "tools": _array(props.get("tools", []), f"results[{i}].properties.tools"),
                "risk_level": severity,
            }
            if "graph_path" in props:
                chain["graph_path"] = _array(props["graph_path"], f"results[{i}] graph_path")
            chains.append(chain)
            continue
        if props.get("needs_review") is True:  # a note: listed, counted in no gate
            attacks.append(
                {
                    "vector_id": row["ruleId"],
                    "successful": False,
                    "evidence": {"needs_review": True, "signals": props.get("signals", [])},
                }
            )
            continue
        rule = rules.get(str(row["ruleId"]), {})
        rule_props = _mapping(rule.get("properties", {}), f"rule {row['ruleId']} properties")
        tags = [str(t) for t in _array(rule_props.get("tags", []), f"rule {row['ruleId']} tags")]
        attacks.append(
            {
                "vector_id": row["ruleId"],
                "vector_name": rule.get("name", row["ruleId"]),
                "category": tags[0] if tags else "unknown",
                "severity": severity,
                "owasp_mapping": [t.removeprefix("owasp/") for t in tags if t.startswith("owasp/")],
                "successful": True,
            }
        )

    # the SARIF lists successful attacks only; the gate counts every attack run (nothing_measured)
    count = gate_inputs["attack_count"]
    valid = isinstance(count, int) and not isinstance(count, bool)
    if not valid or not len(attacks) <= count <= _MAX_ATTACK_COUNT:
        msg = (
            f"SARIF attack_count {count!r} must be an integer from {len(attacks)} "
            f"to {_MAX_ATTACK_COUNT}"
        )
        raise ValueError(msg)
    attacks += [{"successful": False}] * (count - len(attacks))

    phase_vulns = _mapping(gate_inputs.get("phase_vulnerabilities", {}), "phase_vulnerabilities")
    return CampaignResult.model_validate(
        {
            "campaign_id": gate_inputs.get("campaign_id", "sarif"),
            "target_agent": gate_inputs["target_agent"],
            "phases_executed": [
                {
                    "phase": phase,
                    "success": True,
                    "trust_score": gate_inputs["final_trust_score"],
                    "duration_seconds": 0.0,
                    "vulnerabilities_found": vulns,
                }
                for phase, vulns in phase_vulns.items()
            ],
            "total_vulnerabilities": 0,
            "critical_paths": gate_inputs.get("critical_paths", []),
            "final_trust_score": gate_inputs["final_trust_score"],
            "success": gate_inputs["success"],
            "attack_results": attacks,
            "dangerous_tool_chains": chains,
            "metadata": gate_inputs.get("metadata", {}),
        }
    )


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

    # The exact severity (level ``error`` is both critical and high), then any evidence
    sarif_result["properties"] = {"severity": severity}
    evidence = ar.get("evidence", {})
    if evidence:
        sarif_result["properties"]["evidence"] = evidence
    trials = evidence.get("trials") if isinstance(evidence, dict) else None
    if trials:  # repeat trials (spec 121): successes out of k, flaky when some but not all
        sarif_result["properties"] |= {
            "successes": trials["successes"],
            "trials": trials["k"],
            "measured": trials.get("measured", trials["k"]),
            "success_rate": trials["success_rate"],
            "flaky": trials["flaky"],
        }

    return sarif_result
