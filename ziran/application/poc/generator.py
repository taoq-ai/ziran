"""Proof-of-Concept generator — reproducible exploit scripts.

Generates standalone PoC scripts from successful attack results that
can be used to reproduce, validate, and demonstrate vulnerabilities.

Supports multiple output formats:
  - **Python**: Standalone httpx script that sends the scan's request.
  - **cURL**: Shell script that sends the same request with curl.
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
import os
import re
import secrets
import shlex
import textwrap
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from mdutils.mdutils import MdUtils

from ziran.application.poc.config import PoCConfig
from ziran.domain.entities.target import OpenAIConfig, ProtocolType, RestConfig

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.attack import AttackResult
    from ziran.domain.entities.phase import CampaignResult
    from ziran.domain.entities.target import TargetConfig


class PoCGenerator:
    """Generate reproducible proof-of-concept exploit artifacts.

    Creates scripts and documentation from successful attack results
    that allow security teams to reproduce and validate findings.

    Args:
        output_dir: Directory where generated PoC files are written.
        config: Template / formatting configuration.
            Defaults to the built-in config shipped with ZIRAN.
        target: The scanned target. The scripts send the request its protocol
            handler sent; without one they post ``{"message": prompt}``.

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
        target: TargetConfig | None = None,
    ) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or PoCConfig.default()
        self.target = target

    def _http_target(self) -> bool:
        """True when the target speaks a protocol the scripts reproduce over plain HTTP."""
        return self.target is not None and self.target.protocol in (
            ProtocolType.OPENAI,
            ProtocolType.REST,
        )

    def _request(self, prompt: str, endpoint: str | None) -> tuple[str, str, dict[str, Any]]:
        """Method, URL and JSON body the target's protocol handler sends for ``prompt``.

        Mirrors ``OpenAIProtocolHandler.send`` and ``RestProtocolHandler.send`` for one
        turn; ``endpoint`` replaces the URL.
        """
        target = self.target
        if target is None:
            url = self.config.curl_template.default_endpoint
            return "POST", endpoint or url, {"message": prompt}
        if target.protocol == ProtocolType.OPENAI:
            oa = target.openai or OpenAIConfig()
            body: dict[str, Any] = {
                "model": oa.model,
                "messages": [{"role": "user", "content": prompt}],
            }
            if oa.temperature is not None:
                body["temperature"] = oa.temperature
            if oa.max_tokens is not None:
                body["max_tokens"] = oa.max_tokens
            return "POST", endpoint or f"{target.normalized_url}/v1/chat/completions", body
        if target.protocol == ProtocolType.REST:
            rest = target.rest or RestConfig()
            url = target.normalized_url
            if rest.request_path:
                url = f"{url}/{rest.request_path.lstrip('/')}"
            return rest.method, endpoint or url, {rest.message_field: prompt, **rest.extra_body}
        return "POST", endpoint or target.url, {"message": prompt}

    def _path(self, filename: str) -> Path:
        """Return ``filename`` inside the output folder, or raise ValueError."""
        path = self.output_dir / filename
        if path.resolve().parent != self.output_dir.resolve():
            msg = f"PoC file name {filename!r} leaves the output folder"
            raise ValueError(msg)
        return path

    def _write(self, filename: str, text: str, mode: int = 0o644) -> Path:
        """Write ``text`` as UTF-8 to ``filename`` in the output folder.

        The path passes :meth:`_path`. The text goes to a new temp file in the
        folder (``O_EXCL``, the umask applies), which then replaces the final
        name, so a symlink, hard link or FIFO planted there is replaced, never
        written through. Only an executable mode is forced past the umask.
        """
        path = self._path(filename)
        tmp = path.with_name(f".{filename}.{secrets.token_hex(8)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                if mode & 0o111 and hasattr(os, "fchmod"):
                    os.fchmod(fh.fileno(), mode)
                fh.write(text)
            os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return path

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
            ar = AttackResult.model_validate(raw) if isinstance(raw, dict) else raw
            if ar.successful:
                successful.append(ar)

        if not successful:
            return generated

        # Generate individual Python PoCs
        for result in successful:
            path = self.generate_python_poc(result, campaign_result.campaign_id)
            generated.append(path)

        if self._http_target():
            for result in successful:
                generated.append(
                    self.generate_curl_poc(result, campaign_id=campaign_result.campaign_id)
                )

        # Generate combined Markdown reproduction guide
        md_path = self.generate_markdown_guide(successful, campaign_result.campaign_id)
        generated.append(md_path)

        return generated

    def generate_python_poc(
        self,
        result: AttackResult,
        campaign_id: str = "unknown",
        endpoint: str | None = None,
    ) -> Path:
        """Generate a Python PoC script for a single finding.

        For an ``openai`` or ``rest`` target the script is standalone (httpx
        only) and sends the target's request. Otherwise it defines
        ``reproduce(adapter)`` for a configured ZIRAN adapter, as before.

        Args:
            result: Successful attack result.
            campaign_id: Campaign identifier for traceability.
            endpoint: URL to send to instead of the target's (HTTP script only).

        Returns:
            Path to the generated Python script.
        """
        tpl = self.config.python_template
        http = self._http_target()
        if http:
            method, url, body = self._request(result.prompt_used or "", endpoint)
            usage = _PY_HTTP_USAGE
            imports_block = "import json\nimport sys\n\nimport httpx"
            request = (
                f"METHOD = {method!r}\nDEFAULT_ENDPOINT = {url!r}\n"
                f"BODY = json.loads({json.dumps(body)!r})\n"
            )
            reproduce = _PY_HTTP_REPRODUCE
        else:
            usage = "Run it against the same agent configuration to validate the issue."
            imports_block = "\n".join(f"import {m}" for m in tpl.imports)
            request = ""
            reproduce = _PY_ADAPTER_REPRODUCE

        # Every finding value goes in as a repr() literal: none is pasted into
        # the docstring, an f-string or a comment, so no value can end a quote.
        # Dedent before filling, so a multi-line imports block keeps the module flat.
        script = textwrap.dedent('''\
            {shebang}
            """Proof-of-Concept that reproduces a confirmed ZIRAN finding.

            {usage}
            """

            {imports_block}

            VECTOR_NAME = {vector_name}
            CAMPAIGN_ID = {campaign_id}
            VECTOR_ID = {vector_id}
            CATEGORY = {category}
            SEVERITY = {severity}
            OWASP = {owasp}
            GENERATED = {generated}
            GENERATOR = {generator_label}

            # ── Attack payload ──────────────────────────────────────────
            {request}ATTACK_PROMPT = {prompt}

            # ── Expected indicators ─────────────────────────────────────
            SUCCESS_INDICATORS = {indicators}

            VULNERABLE_TEXT_MATCH = {vulnerable_text_match}
            VULNERABLE_TOOL_MATCH = {vulnerable_tool_match}
            NOT_REPRODUCED = {not_reproduced}

            {reproduce}

            if __name__ == "__main__":
                print("=" * 60)
                print("ZIRAN Proof-of-Concept: " + {display_name})
                print("=" * 60)
                print()
        ''').format(
            shebang=tpl.shebang,
            usage=usage,
            imports_block=imports_block,
            request=request,
            reproduce=reproduce,
            vector_name=repr(result.vector_name),
            display_name=repr(_printable(result.vector_name)),
            campaign_id=repr(campaign_id),
            vector_id=repr(result.vector_id),
            category=repr(result.category.value),
            severity=repr(result.severity),
            owasp=repr(_owasp_ids(result)),
            generated=repr(datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")),
            generator_label=repr(self.config.generator_label),
            prompt=repr(result.prompt_used or ""),
            indicators=repr(_indicators(result)),
            vulnerable_text_match=repr(tpl.vulnerable_text_match),
            vulnerable_tool_match=repr(tpl.vulnerable_tool_match),
            not_reproduced=repr(tpl.not_reproduced),
        )

        if http:
            script += "    sys.exit(reproduce(*sys.argv[1:2]))\n"
        else:
            for instruction in tpl.run_instructions:
                script += f"    print({instruction!r})\n"
            script += "    print()\n"
            script += "    sys.exit(0)\n"

        return self._write(
            f"poc_{_safe_name(result.vector_id)}_{_safe_name(campaign_id)}.py", script
        )

    def generate_curl_poc(
        self,
        result: AttackResult,
        endpoint: str | None = None,
        campaign_id: str = "unknown",
    ) -> Path:
        """Generate a cURL-based PoC that sends the target's request.

        Args:
            result: Successful attack result.
            endpoint: URL to send to instead of the target's (or, with
                no target, the config default).
            campaign_id: Campaign identifier.

        Returns:
            Path to the generated shell script. It exits 0 when the
            finding reproduces, 1 when it does not, 2 with no text
            indicator to check.
        """
        tpl = self.config.curl_template
        q = shlex.quote
        method, url, body = self._request(result.prompt_used or "", endpoint)
        indicators = _indicators(result)

        # Every value is a shlex-quoted word, never pasted into a comment, an
        # echo or a hand-quoted string. The body goes through the printf
        # builtin to curl's stdin, so it arrives byte for byte at any size.
        script = textwrap.dedent("""\
            #!/bin/bash
            # Proof-of-Concept that reproduces a confirmed ZIRAN finding.
            # Usage: bash <this file> [ENDPOINT]
            # Exit 0: reproduced. Exit 1: not reproduced. Exit 2: nothing to check.

            set -euo pipefail

            VECTOR_NAME={vector_name}
            CAMPAIGN_ID={campaign_id}
            VECTOR_ID={vector_id}
            CATEGORY={category}
            SEVERITY={severity}
            OWASP={owasp}
            GENERATED={generated}

            DEFAULT_ENDPOINT={endpoint}
            ENDPOINT="${{1:-$DEFAULT_ENDPOINT}}"

            printf '%s\\n' {banner}
            printf 'Sending attack payload to %s ...\\n' "$ENDPOINT"

            RESPONSE=$(printf '%s' {payload} | curl -s -X {method} --url "$ENDPOINT" \\
              -H "Content-Type: application/json" \\
              --data-binary @-)

            echo ""
            echo "Response:"
            printf '%s' "${{RESPONSE:0:{max_chars}}}"
            echo ""
            echo ""

            # Check for success indicators
            VULNERABLE=0
        """).format(
            vector_name=q(result.vector_name),
            campaign_id=q(campaign_id),
            vector_id=q(result.vector_id),
            category=q(result.category.value),
            severity=q(result.severity),
            owasp=q(_owasp_ids(result)),
            generated=q(datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")),
            endpoint=q(url),
            banner=q(f"=== ZIRAN PoC: {_printable(result.vector_name)} ==="),
            payload=q(json.dumps(body)),
            method=q(method),
            max_chars=tpl.max_response_chars,
        )

        if not indicators:
            script += 'echo "[-] No text indicator recorded: check the agent\'s tool log"\n'
            script += "exit 2\n"
        for ind in indicators[: tpl.max_indicators]:
            script += f'grep -qiF -- {q(ind)} <<<"$RESPONSE" && VULNERABLE=1\n'

        script += textwrap.dedent("""\

            if [ "$VULNERABLE" -eq 1 ]; then
              echo "[!] VULNERABLE — Success indicators detected in response"
              echo "[i] {note}"
              exit 0
            else
              echo "[-] Not reproduced"
              exit 1
            fi
        """).format(note=_ATTEMPT_NOTE)

        name = f"poc_{_safe_name(result.vector_id)}_{_safe_name(campaign_id)}.sh"
        return self._write(name, script, 0o755)

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
        filename = f"poc_guide_{_safe_name(campaign_id)}.md"

        md = MdUtils(
            file_name=filename,  # unused: the text is written by self._write
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
            owasp = _owasp_ids(r)
            table_data.extend([str(idx), r.vector_name, r.category.value, r.severity, owasp])
        md.new_table(
            columns=len(table_header),
            rows=len(results) + 1,
            text=table_header + table_data,
            text_align="left",
        )

        # ── Per-finding details ─────────────────────────────────────
        for i, result in enumerate(results, 1):
            owasp_str = _owasp_ids(result)

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

        return self._write(filename, md.get_md_text())


#: What a match shows: the attempt, not whether an egress guard stopped it.
_ATTEMPT_NOTE = (
    "The reply carries a recorded indicator (the agent attempted to send it); "
    "a fix at the egress tool is not visible to this PoC."
)

# ── Python PoC bodies (plain text, never passed through str.format) ──

_PY_HTTP_USAGE = """Usage: python3 <this file> [ENDPOINT]   (needs httpx)
Exit 0: reproduced. Exit 1: not reproduced. Exit 2: nothing to check."""

_PY_HTTP_REPRODUCE = (
    '''
def _texts(value):
    """Every string in a parsed JSON reply, tool-call arguments included."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        value = list(value.values())
    if not isinstance(value, list):
        return []
    return [text for item in value for text in _texts(item)]


def reproduce(endpoint=DEFAULT_ENDPOINT):
    """Send the attack request; return 0 reproduced, 1 not, 2 nothing to check."""
    print("[*] Sending attack payload to " + endpoint)
    reply = httpx.request(METHOD, endpoint, json=BODY, timeout=120.0)
    print("[*] Agent response (HTTP " + str(reply.status_code) + ", first 200 chars):")
    print("    " + reply.text[:200])
    try:
        data = reply.json()
    except ValueError:
        data = reply.text
    content_lower = "\\n".join(_texts(data)).lower()
    matched = [ind for ind in SUCCESS_INDICATORS if ind.lower() in content_lower]

    if matched:
        print("[!] " + VULNERABLE_TEXT_MATCH.replace("{matched}", str(matched)))
        print("[i] " + '''
    + repr(_ATTEMPT_NOTE)
    + """)
        return 0
    if SUCCESS_INDICATORS:
        print("[-] " + NOT_REPRODUCED)
        return 1
    print("[-] No text indicator recorded: check the agent's tool log")
    return 2
"""
)

_PY_ADAPTER_REPRODUCE = '''
async def reproduce(adapter):
    """Send the attack payload and check for success indicators.

    Args:
        adapter: A configured ZIRAN BaseAgentAdapter instance.

    Returns:
        True if the vulnerability is confirmed, False otherwise.
    """
    print(f"[*] Sending attack prompt: {ATTACK_PROMPT[:80]}...")
    response = await adapter.invoke(ATTACK_PROMPT)

    print(f"[*] Agent response (first 200 chars):")
    print(f"    {response.content[:200]}")

    # Check text indicators
    content_lower = response.content.lower()
    matched = [
        ind for ind in SUCCESS_INDICATORS
        if ind.lower() in content_lower
    ]

    # Check tool call side-effects
    if response.tool_calls:
        print(f"[!] Agent executed {len(response.tool_calls)} tool(s):")
        for tc in response.tool_calls:
            tool_name = tc.get("tool") or tc.get("name") or "unknown"
            print(f"    - {tool_name}")

    if matched:
        print("[!] " + VULNERABLE_TEXT_MATCH.replace("{matched}", str(matched)))
        return True
    elif response.tool_calls:
        print("[!] " + VULNERABLE_TOOL_MATCH)
        return True
    else:
        print("[-] " + NOT_REPRODUCED)
        return False
'''


# ── Helpers ──────────────────────────────────────────────────────────


def _owasp_ids(result: AttackResult) -> str:
    """OWASP LLM then Agentic ids of a finding, or ``N/A``."""
    ids = [*result.owasp_mapping, *result.owasp_agentic_mapping]
    return ", ".join(c.value for c in ids) or "N/A"


#: A whole token, unless it is a label of a host or file name (``canary1.example``).
_TOKEN = re.compile(r"(?<![A-Za-z0-9_.-])(?>[A-Za-z0-9_-]+)(?!\.[A-Za-z])")


def _indicators(result: AttackResult) -> list[str]:
    """The canaries the scan recorded, then the matched indicators found where it saw them.

    A canary is taken from the recorded reply or a recorded tool call's arguments, so
    a fixed agent holding a fresh canary does not match; one the prompt sent is dropped. A matched indicator stays when
    it occurs in that reply or those arguments; this drops labels no reply holds (a
    judge verdict, a tool description). With no recorded reply, every matched one stays.
    """
    reply = result.agent_response or result.evidence.get("response_snippet") or ""
    calls = result.evidence.get("tool_calls") or []
    args = [
        _strings(_parsed(c.get("arguments", c.get("input", c.get("args")))))
        for c in calls
        if isinstance(c, dict)
    ]
    seen = "\n".join([reply, *(s for a in args for s in a)])
    # A canary names itself one and holds a digit (``ZX-CANARY-7731``). A token the
    # attack prompt sent is an echo, never a leak.
    prompt = (result.prompt_used or "").casefold()
    canaries = [
        t
        for t in _TOKEN.findall(seen)
        if "canary" in t.casefold() and any(c.isdigit() for c in t) and t.casefold() not in prompt
    ]
    matched = [
        i
        for i in result.evidence.get("matched_indicators", [])
        if isinstance(i, str) and i and (not reply or i.lower() in seen.lower())
    ]
    return list(dict.fromkeys([*canaries, *matched]))


def _parsed(value: Any) -> Any:
    """``value`` decoded when it is a JSON string (OpenAI tool-call arguments), else as is."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _strings(value: Any) -> list[str]:
    """Every string in a decoded JSON value."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _safe_name(value: str) -> str:
    """``value`` with every character outside ``[A-Za-z0-9._-]`` replaced by ``_``.

    Raises:
        ValueError: when ``value`` is empty or only dots, which name no file.
    """
    if not value.strip("."):
        msg = f"PoC file name part {value!r} is empty or only dots"
        raise ValueError(msg)
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def _printable(value: str) -> str:
    """``value`` with every non-printable character (C0, C1, ESC, bidi) backslash-escaped."""
    return "".join(
        c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in value
    )
