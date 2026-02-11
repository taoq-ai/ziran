"""GitHub Actions integration helpers.

Provides functions that emit `workflow commands
<https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions>`_
recognised by the GitHub Actions runner, including annotations,
output variables, and job summaries.

Usage::

    from ziran.application.cicd.github_actions import (
        emit_annotations,
        write_step_summary,
        set_output,
    )

    emit_annotations(campaign_result)
    write_step_summary(gate_result, campaign_result)
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ziran.domain.entities.ci import GateResult


def emit_annotations(
    result: Any,  # CampaignResult
) -> list[str]:
    """Emit ``::error`` / ``::warning`` workflow commands for each finding.

    Returns:
        List of annotation strings (also printed to stdout when
        running inside GitHub Actions).
    """
    annotations: list[str] = []
    for raw in result.attack_results:
        ar: dict[str, Any] = raw if isinstance(raw, dict) else raw.model_dump()  # type: ignore[union-attr]
        if not ar.get("successful"):
            continue

        severity: str = ar.get("severity", "medium")
        level = "error" if severity in ("critical", "high") else "warning"
        vector_name = ar.get("vector_name", ar.get("vector_id", "unknown"))
        category = ar.get("category", "unknown")
        owasp = ar.get("owasp_mapping", [])
        owasp_str = ", ".join(owasp) if owasp else "N/A"

        title = f"[{severity.upper()}] {vector_name}"
        msg = (
            f"Category: {category} | OWASP: {owasp_str} | Vector: {ar.get('vector_id', 'unknown')}"
        )

        annotation = f"::{level} title={title}::{msg}"
        annotations.append(annotation)

    return annotations


def write_step_summary(
    gate: GateResult,
    result: Any,  # CampaignResult
    *,
    summary_path: str | None = None,
) -> str:
    """Write a Markdown summary to ``$GITHUB_STEP_SUMMARY``.

    If *summary_path* is ``None``, the function reads the
    ``GITHUB_STEP_SUMMARY`` environment variable.  Outside GitHub
    Actions the summary is returned but not written.

    Returns:
        The Markdown summary string.
    """
    counts = gate.finding_counts
    status_emoji = "\u2705" if gate.passed else "\u274c"
    status_text = "PASSED" if gate.passed else "FAILED"

    lines: list[str] = [
        f"## {status_emoji} ZIRAN Security Gate: {status_text}",
        "",
        f"**Target agent:** `{result.target_agent}`  ",
        f"**Campaign:** `{result.campaign_id}`  ",
        f"**Trust score:** `{result.final_trust_score:.2f}`  ",
        "",
        "### Finding Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {counts.critical} |",
        f"| High     | {counts.high} |",
        f"| Medium   | {counts.medium} |",
        f"| Low      | {counts.low} |",
        f"| **Total** | **{counts.total}** |",
        "",
    ]

    if gate.violations:
        lines.append("### Gate Violations")
        lines.append("")
        lines.append("| Rule | Message | Severity |")
        lines.append("|------|---------|----------|")
        for v in gate.violations:
            lines.append(f"| {v.rule} | {v.message} | {v.severity} |")
        lines.append("")

    # Successful attacks detail table
    successful = [
        (r if isinstance(r, dict) else r.model_dump())  # type: ignore[union-attr]
        for r in result.attack_results
        if (r if isinstance(r, dict) else r.model_dump()).get("successful")  # type: ignore[union-attr]
    ]
    if successful:
        lines.append("### Vulnerabilities Found")
        lines.append("")
        lines.append("| Vector | Category | Severity | OWASP |")
        lines.append("|--------|----------|----------|-------|")
        for ar in successful[:20]:  # cap at 20 rows
            owasp = ", ".join(ar.get("owasp_mapping", []))
            lines.append(
                f"| {ar.get('vector_name', 'N/A')} "
                f"| {ar.get('category', 'N/A')} "
                f"| {ar.get('severity', 'N/A')} "
                f"| {owasp or 'N/A'} |"
            )
        if len(successful) > 20:
            lines.append(f"| ... and {len(successful) - 20} more | | | |")
        lines.append("")

    summary = "\n".join(lines)

    # Write to GITHUB_STEP_SUMMARY if available
    target = summary_path or os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a") as fh:
            fh.write(summary)
            fh.write("\n")

    return summary


def set_output(name: str, value: str) -> str:
    """Append a ``name=value`` pair to ``$GITHUB_OUTPUT``.

    Returns:
        The output line that was written.
    """
    line = f"{name}={value}"
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as fh:
            fh.write(line)
            fh.write("\n")
    return line
