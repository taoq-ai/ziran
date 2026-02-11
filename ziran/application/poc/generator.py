"""Proof-of-Concept generator — reproducible exploit scripts.

Generates standalone PoC scripts from successful attack results that
can be used to reproduce, validate, and demonstrate vulnerabilities.

Supports multiple output formats:
  - **Python**: Complete asyncio script using the adapter pattern.
  - **cURL**: HTTP-based PoC for API-accessible agents.
  - **Markdown**: Human-readable reproduction steps.

All template text, formatting options, and labels are loaded from a
:class:`~.config.PoCConfig` (backed by YAML) so organisations can
customise the output without code changes.

Example::

    config = PoCConfig.default()
    generator = PoCGenerator(output_dir=Path("./pocs"), config=config)
    for result in campaign.attack_results:
        if result.successful:
            generator.generate_python_poc(result, campaign_id="abc123")
"""

from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from mdutils.mdutils import MdUtils

from ziran.application.poc.config import PoCConfig

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.attack import AttackResult
    from ziran.domain.entities.phase import CampaignResult


class PoCGenerator:
    """Generate reproducible proof-of-concept exploit artifacts.

    Creates scripts and documentation from successful attack results
    that allow security teams to reproduce and validate findings.

    Args:
        output_dir: Directory where generated PoC files are written.
        config: Template / formatting configuration.
            Defaults to the built-in config shipped with ZIRAN.

    Example::

        generator = PoCGenerator(output_dir=Path("./pocs"))
        for result in campaign.attack_results:
            if result.successful:
                generator.generate_python_poc(result, campaign_id="abc123")
    """

    def __init__(
        self,
        output_dir: Path,
        config: PoCConfig | None = None,
    ) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or PoCConfig.default()

    def generate_all(
        self,
        campaign_result: CampaignResult,
    ) -> list[Path]:
        """Generate PoCs for all successful attacks in a campaign.

        Args:
            campaign_result: Full campaign result with attack_results.

        Returns:
            List of paths to generated PoC files.
        """
        from ziran.domain.entities.attack import AttackResult

        generated: list[Path] = []

        # attack_results in CampaignResult are serialized dicts
        successful: list[AttackResult] = []
        for raw in campaign_result.attack_results:
            ar = (
                AttackResult.model_validate(raw) if isinstance(raw, dict) else raw  # type: ignore[assignment]
            )
            if ar.successful:
                successful.append(ar)

        if not successful:
            return generated

        # Generate individual Python PoCs
        for result in successful:
            path = self.generate_python_poc(result, campaign_result.campaign_id)
            generated.append(path)

        # Generate combined Markdown reproduction guide
        md_path = self.generate_markdown_guide(successful, campaign_result.campaign_id)
        generated.append(md_path)

        return generated

    def generate_python_poc(
        self,
        result: AttackResult,
        campaign_id: str = "unknown",
    ) -> Path:
        """Generate a standalone Python PoC script for a single finding.

        Args:
            result: Successful attack result.
            campaign_id: Campaign identifier for traceability.

        Returns:
            Path to the generated Python script.
        """
        tpl = self.config.python_template
        owasp_str = ", ".join(c.value for c in result.owasp_mapping) or "N/A"
        prompt_escaped = _escape_python_string(result.prompt_used or "")
        indicators = result.evidence.get("matched_indicators", [])
        indicators_repr = repr(indicators)
        result.evidence.get("tool_calls", [])
        result.evidence.get("side_effects", {})

        imports_block = "\n".join(f"import {m}" for m in tpl.imports)

        script = textwrap.dedent(f'''\
            {tpl.shebang}
            """Proof-of-Concept: {result.vector_name}

            Campaign:  {campaign_id}
            Vector:    {result.vector_id}
            Category:  {result.category.value}
            Severity:  {result.severity}
            OWASP:     {owasp_str}

            Generated: {datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}
            Generator: {self.config.generator_label}

            This script reproduces a confirmed vulnerability finding.
            Run it against the same agent configuration to validate the issue.
            """

            {imports_block}


            # ── Attack payload ──────────────────────────────────────────
            ATTACK_PROMPT = """{prompt_escaped}"""

            # ── Expected indicators ─────────────────────────────────────
            SUCCESS_INDICATORS = {indicators_repr}


            async def reproduce(adapter):
                """Send the attack payload and check for success indicators.

                Args:
                    adapter: A configured ZIRAN BaseAgentAdapter instance.

                Returns:
                    True if the vulnerability is confirmed, False otherwise.
                """
                print(f"[*] Sending attack prompt: {{ATTACK_PROMPT[:80]}}...")
                response = await adapter.invoke(ATTACK_PROMPT)

                print(f"[*] Agent response (first 200 chars):")
                print(f"    {{response.content[:200]}}")

                # Check text indicators
                content_lower = response.content.lower()
                matched = [
                    ind for ind in SUCCESS_INDICATORS
                    if ind.lower() in content_lower
                ]

                # Check tool call side-effects
                if response.tool_calls:
                    print(f"[!] Agent executed {{len(response.tool_calls)}} tool(s):")
                    for tc in response.tool_calls:
                        tool_name = tc.get("tool") or tc.get("name") or "unknown"
                        print(f"    - {{tool_name}}")

                if matched:
                    print(f"[!] {tpl.vulnerable_text_match}")
                    return True
                elif response.tool_calls:
                    print(f"[!] {tpl.vulnerable_tool_match}")
                    return True
                else:
                    print(f"[-] {tpl.not_reproduced}")
                    return False


            if __name__ == "__main__":
                print("=" * 60)
                print("ZIRAN Proof-of-Concept: {result.vector_name}")
                print("=" * 60)
                print()
        ''')

        # Append run instructions from config
        for instruction in tpl.run_instructions:
            script += f'    print("{instruction}")\n'

        script += "    print()\n"
        script += "    sys.exit(0)\n"

        filename = f"poc_{result.vector_id}_{campaign_id}.py"
        filepath = self.output_dir / filename
        filepath.write_text(script)
        return filepath

    def generate_curl_poc(
        self,
        result: AttackResult,
        endpoint: str | None = None,
        campaign_id: str = "unknown",
    ) -> Path:
        """Generate a cURL-based PoC for API-accessible agents.

        Args:
            result: Successful attack result.
            endpoint: The agent's HTTP endpoint.  Falls back to
                the config default if not given.
            campaign_id: Campaign identifier.

        Returns:
            Path to the generated shell script.
        """
        tpl = self.config.curl_template
        effective_endpoint = endpoint or tpl.default_endpoint
        prompt_json = json.dumps({"message": result.prompt_used or ""})
        owasp_str = ", ".join(c.value for c in result.owasp_mapping) or "N/A"
        indicators = result.evidence.get("matched_indicators", [])

        script = textwrap.dedent(f"""\
            #!/bin/bash
            # Proof-of-Concept: {result.vector_name}
            #
            # Campaign:  {campaign_id}
            # Vector:    {result.vector_id}
            # Category:  {result.category.value}
            # Severity:  {result.severity}
            # OWASP:     {owasp_str}
            # Generated: {datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}

            set -euo pipefail

            ENDPOINT="${{1:-{effective_endpoint}}}"

            echo "=== ZIRAN PoC: {result.vector_name} ==="
            echo "Sending attack payload to $ENDPOINT ..."

            RESPONSE=$(curl -s -X POST "$ENDPOINT" \\
              -H "Content-Type: application/json" \\
              -d '{prompt_json}')

            echo ""
            echo "Response:"
            echo "$RESPONSE" | head -c {tpl.max_response_chars}
            echo ""
            echo ""

            # Check for success indicators
            VULNERABLE=0
        """)

        for ind in indicators[: tpl.max_indicators]:
            ind_escaped = ind.replace("'", "'\\''")
            script += f"    echo \"$RESPONSE\" | grep -qi '{ind_escaped}' && VULNERABLE=1\n"

        script += textwrap.dedent("""\

            if [ "$VULNERABLE" -eq 1 ]; then
              echo "[!] VULNERABLE — Success indicators detected in response"
              exit 1
            else
              echo "[-] Not reproduced"
              exit 0
            fi
        """)

        filename = f"poc_{result.vector_id}_{campaign_id}.sh"
        filepath = self.output_dir / filename
        filepath.write_text(script)
        filepath.chmod(0o755)
        return filepath

    def generate_markdown_guide(
        self,
        results: list[AttackResult],
        campaign_id: str = "unknown",
    ) -> Path:
        """Generate a Markdown reproduction guide for all findings.

        Uses *mdutils* to build structured Markdown programmatically.

        Args:
            results: List of successful attack results.
            campaign_id: Campaign identifier.

        Returns:
            Path to the generated Markdown file.
        """
        tpl = self.config.markdown_template
        filepath = self.output_dir / f"poc_guide_{campaign_id}.md"

        md = MdUtils(
            file_name=str(filepath.with_suffix("")),  # mdutils appends .md
            title=tpl.title,
        )

        # ── Summary metadata ────────────────────────────────────────
        timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        md.new_paragraph(f"**Campaign:** `{campaign_id}`  ")
        md.new_line(f"**Generated:** {timestamp}  ")
        md.new_line(f"**Findings:** {len(results)} confirmed vulnerabilities")

        # Summary table
        table_header = ["#", "Finding", "Category", "Severity", "OWASP"]
        table_data: list[str] = []
        for idx, r in enumerate(results, 1):
            owasp = ", ".join(c.value for c in r.owasp_mapping) or "N/A"
            table_data.extend([str(idx), r.vector_name, r.category.value, r.severity, owasp])
        md.new_table(
            columns=len(table_header),
            rows=len(results) + 1,
            text=table_header + table_data,
            text_align="left",
        )

        # ── Per-finding details ─────────────────────────────────────
        for i, result in enumerate(results, 1):
            owasp_str = ", ".join(c.value for c in result.owasp_mapping) or "N/A"

            md.new_header(level=2, title=f"{i}. {result.vector_name}", add_table_of_contents="n")

            md.new_list(
                [
                    f"**Vector ID:** `{result.vector_id}`",
                    f"**Category:** `{result.category.value}`",
                    f"**Severity:** `{result.severity}`",
                    f"**OWASP:** {owasp_str}",
                ]
            )

            # Reproduction steps
            md.new_header(level=3, title="Reproduction Steps", add_table_of_contents="n")
            md.new_list(
                [
                    "Configure your agent with the same tools/permissions as the test target.",
                    "Send the following prompt to the agent:",
                ],
                marked_with="1",
            )

            md.insert_code(
                result.prompt_used or "(prompt not captured)",
            )

            md.new_list(
                ["Verify the response contains these indicators:"],
                marked_with="1",
            )

            indicators = result.evidence.get("matched_indicators", [])
            if indicators:
                md.new_list([f"`{ind}`" for ind in indicators])
            else:
                md.new_paragraph(
                    "*(check for tool execution in agent logs)*",
                    bold_italics_code="i",
                )

            # Tool calls observed
            tool_calls = result.evidence.get("tool_calls", [])
            if tool_calls:
                md.new_header(level=3, title="Observed Tool Executions", add_table_of_contents="n")
                tool_names = [
                    f"`{tc.get('tool') or tc.get('name') or 'unknown'}`" for tc in tool_calls
                ]
                md.new_list(tool_names)

            # Agent response snippet
            snippet = result.evidence.get("response_snippet", "")
            if snippet:
                md.new_header(level=3, title="Agent Response (snippet)", add_table_of_contents="n")
                md.insert_code(snippet[: tpl.max_response_snippet_chars])

            # Detector reasoning
            reasoning = result.evidence.get("detector_reasoning", "")
            if reasoning:
                md.new_header(level=3, title="Detection Reasoning", add_table_of_contents="n")
                md.new_paragraph(f"> {reasoning}")

            md.new_paragraph("---")

        # ── Footer ──────────────────────────────────────────────────
        ziran_link = md.new_inline_link(link=tpl.footer_link_url, text=tpl.footer_link_text)
        md.new_paragraph(f"*Generated by {ziran_link} — {tpl.footer_tagline}*")

        md.create_md_file()
        return filepath


# ── Helpers ──────────────────────────────────────────────────────────


def _escape_python_string(s: str) -> str:
    """Escape a string for safe embedding in a triple-quoted Python string."""
    return s.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
