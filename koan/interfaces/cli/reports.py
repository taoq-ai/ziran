"""Report generation — JSON and Markdown formatters.

Transforms CampaignResult into human-readable reports and
machine-parseable JSON output.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from koan.domain.entities.phase import CampaignResult


class ReportGenerator:
    """Generates reports from campaign results.

    Supports JSON (machine-parseable) and Markdown (human-readable)
    output formats.

    Example:
        ```python
        generator = ReportGenerator(output_dir=Path("./results"))
        generator.save_json(result)
        generator.save_markdown(result)
        ```
    """

    def __init__(self, output_dir: Path) -> None:
        """Initialize the report generator.

        Args:
            output_dir: Directory to write reports to.
        """
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save_json(self, result: CampaignResult) -> Path:
        """Save campaign result as JSON.

        Args:
            result: The campaign result to serialize.

        Returns:
            Path to the saved JSON file.
        """
        filepath = self.output_dir / f"{result.campaign_id}_report.json"
        data = result.model_dump(mode="json")

        with filepath.open("w") as f:
            json.dump(data, f, indent=2, default=str)

        return filepath

    def save_markdown(self, result: CampaignResult) -> Path:
        """Save campaign result as a Markdown report.

        Args:
            result: The campaign result to format.

        Returns:
            Path to the saved Markdown file.
        """
        filepath = self.output_dir / f"{result.campaign_id}_report.md"
        content = self._format_markdown(result)

        with filepath.open("w") as f:
            f.write(content)

        return filepath

    def save_html(
        self,
        result: CampaignResult,
        graph_state: dict[str, Any] | None = None,
    ) -> Path:
        """Save an interactive HTML report with knowledge graph visualization.

        Produces a self-contained HTML file that uses vis-network to render
        the attack knowledge graph, highlights critical attack paths, and
        displays campaign metrics in a sidebar.

        Args:
            result: The campaign result to format.
            graph_state: Full graph export from
                ``AttackKnowledgeGraph.export_state()``.  Falls back to the
                last phase's ``graph_state`` if not provided.

        Returns:
            Path to the saved HTML file.
        """
        from koan.interfaces.cli.html_report import build_html_report

        # Fall back to the last phase's graph snapshot
        if graph_state is None:
            for phase in reversed(result.phases_executed):
                if phase.graph_state:
                    graph_state = phase.graph_state
                    break
            if graph_state is None:
                graph_state = {"nodes": [], "edges": [], "stats": {}}

        result_data = result.model_dump(mode="json")
        html_content = build_html_report(
            result_data=result_data,
            graph_state=graph_state,
        )

        filepath = self.output_dir / f"{result.campaign_id}_report.html"
        with filepath.open("w") as f:
            f.write(html_content)

        return filepath

    def _format_markdown(self, result: CampaignResult) -> str:
        """Format a campaign result as Markdown.

        Args:
            result: The campaign result to format.

        Returns:
            Formatted Markdown string.
        """
        lines: list[str] = []

        # Header
        lines.append("# KOAN Security Scan Report")
        lines.append("")
        lines.append(f"**Campaign ID:** `{result.campaign_id}`")
        lines.append(f"**Target Agent:** `{result.target_agent}`")
        lines.append(f"**Generated:** {datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Phases Executed | {len(result.phases_executed)} |")
        lines.append(f"| Total Vulnerabilities | {result.total_vulnerabilities} |")
        lines.append(f"| Critical Attack Paths | {len(result.critical_paths)} |")
        lines.append(f"| Final Trust Score | {result.final_trust_score:.2f} |")
        lines.append(f"| Overall Result | {'⚠️ VULNERABLE' if result.success else '✅ PASSED'} |")
        lines.append("")

        # Phase Results
        lines.append("## Phase Results")
        lines.append("")

        for phase_result in result.phases_executed:
            status = "🔴" if phase_result.vulnerabilities_found else "🟢"
            lines.append(f"### {status} {phase_result.phase.value.replace('_', ' ').title()}")
            lines.append("")
            lines.append(f"- **Duration:** {phase_result.duration_seconds:.1f}s")
            lines.append(f"- **Trust Score:** {phase_result.trust_score:.2f}")
            lines.append(f"- **Vulnerabilities Found:** {len(phase_result.vulnerabilities_found)}")

            if phase_result.vulnerabilities_found:
                lines.append("")
                lines.append("**Findings:**")
                for vuln_id in phase_result.vulnerabilities_found:
                    artifact = phase_result.artifacts.get(vuln_id, {})
                    name = artifact.get("name", vuln_id)
                    severity = artifact.get("severity", "unknown")
                    category = artifact.get("category", "unknown")
                    lines.append(
                        f"- **{name}** (`{vuln_id}`) — "
                        f"Severity: `{severity}`, Category: `{category}`"
                    )

            if phase_result.error:
                lines.append(f"- **Error:** {phase_result.error}")

            lines.append("")

        # Attack Paths
        if result.critical_paths:
            lines.append("## Critical Attack Paths")
            lines.append("")
            for i, path in enumerate(result.critical_paths[:10], 1):
                lines.append(f"{i}. `{' → '.join(path)}`")
            if len(result.critical_paths) > 10:
                lines.append(f"\n_...and {len(result.critical_paths) - 10} more paths_")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(
            "*Generated by [KOAN](https://github.com/taoq-ai/koan) — "
            "AI Agent Security Testing Framework*"
        )
        lines.append("")

        return "\n".join(lines)
