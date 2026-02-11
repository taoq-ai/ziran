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

import json
from typing import TYPE_CHECKING, Any

from ziran.domain.entities.attack import (
    OWASP_LLM_DESCRIPTIONS,
    OwaspLlmCategory,
)

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.phase import CampaignResult

_SEVERITY_TO_SARIF: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_ZIRAN_VERSION = "0.1.0"


def generate_sarif(result: CampaignResult) -> dict[str, Any]:
    """Generate a SARIF v2.1.0 document from a campaign result.

    Args:
        result: The campaign result to convert.

    Returns:
        A dictionary conforming to the SARIF v2.1.0 JSON schema,
        ready to be serialised with :func:`json.dumps`.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()

    for raw in result.attack_results:
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
        results.append(sarif_result)

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ZIRAN",
                        "version": _ZIRAN_VERSION,
                        "informationUri": "https://github.com/your-org/koan",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(result: CampaignResult, path: Path) -> Path:
    """Generate SARIF and write it to *path*.

    Returns:
        The path that was written.
    """
    sarif = generate_sarif(result)
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
