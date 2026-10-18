"""Drift test for the Claude Code plugin skills (spec 059).

Every ``ziran <command> --flag`` a skill names must exist in the live Click tree, the offline
commands must run against committed examples, the GitHub Action snippet must use declared
inputs, and the chain-type to ATLAS table must cover every chain type with real technique IDs.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import click
import pytest
import yaml
from click.testing import CliRunner, Result

from ziran.domain.entities.attack import AtlasTechnique
from ziran.interfaces.cli.main import cli

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "ziran"
SKILLS = PLUGIN / "skills"
SKILL_NAMES = {"audit-agents", "triage-findings", "set-up-scan", "threat-model-agent"}
ATLAS_TABLE = SKILLS / "threat-model-agent" / "references" / "atlas-chains.md"
KNOWLEDGE_GRAPH = ROOT / "ziran" / "application" / "knowledge_graph"
SAMPLE_RESULT = ROOT / "tests" / "fixtures" / "sample_campaign_result.json"
VULNERABLE_PLUGIN = ROOT / "examples" / "25-claude-code-plugin" / "vulnerable-plugin"
TARGET_LOCAL = ROOT / "examples" / "15-remote-agent-scan" / "target-local.yaml"

FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.S | re.M)
INLINE = re.compile(r"`([^`\n]+)`")
INVOCATION = re.compile(r"(?<![\w/.@-])ziran\s+([a-z][a-z-]*)")
TOKEN_END = re.compile(r"\||;|&&|#|$")
ATLAS_ID = re.compile(r"AML\.T\d{4}(?:\.\d{3})?")


def _skill_files() -> list[Path]:
    return sorted(SKILLS.glob("*/SKILL.md"))


def _frontmatter(text: str) -> dict[str, Any]:
    match = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert match, "SKILL.md must start with a --- frontmatter block"
    data = yaml.safe_load(match.group(1))
    assert isinstance(data, dict)
    return data


def _code_lines(text: str) -> list[str]:
    """Lines of fenced code plus inline code spans; prose is never parsed."""
    lines: list[str] = []
    for block in FENCE.findall(text):
        lines.extend(block.replace("\\\n", " ").splitlines())
    lines.extend(INLINE.findall(FENCE.sub("", text)))
    return lines


def _yaml_blocks(text: str) -> list[Any]:
    blocks = re.findall(r"^```ya?ml\n(.*?)^```", text, re.S | re.M)
    return [yaml.safe_load(b) for b in blocks]


def _check_options(cmd: click.Command, words: list[str], where: str) -> list[str]:
    """Parse *words* with the command's own Click parser; report what Click would reject."""
    try:
        opts, extra, _ = cmd.make_parser(click.Context(cmd)).parse_args(words)
    except click.NoSuchOption as exc:
        return [f"{where} {exc.option_name}: no such option"]
    except click.UsageError as exc:
        return [f"{where}: {exc.message}"]
    errors = [f"{where}: unexpected extra argument {arg}" for arg in extra]
    for param in cmd.params:
        if not isinstance(param.type, click.Choice) or param.name not in opts:
            continue
        values = opts[param.name]
        for value in values if isinstance(values, (list, tuple)) else [values]:
            if not str(value).startswith("<") and value not in param.type.choices:
                flag = max(param.opts, key=len)
                errors.append(f"{where} {flag} {value}: not one of {list(param.type.choices)}")
    return errors


def stale_cli_refs(text: str, label: str) -> list[str]:
    """Every ``ziran <command> --flag`` in code that the live CLI does not accept."""
    errors: list[str] = []
    for line in _code_lines(text):
        for match in INVOCATION.finditer(line):
            name, rest = match.group(1), line[match.end() :]
            words = TOKEN_END.split(rest, maxsplit=1)[0].split()
            cmd: click.Command | None = cli.commands.get(name)
            path = f"ziran {name}"
            while isinstance(cmd, click.Group) and words and words[0] in cmd.commands:
                sub = words.pop(0)
                cmd, path = cmd.commands[sub], f"{path} {sub}"
            if cmd is None:
                errors.append(f"{label}: {path}: no such command")
                continue
            errors.extend(_check_options(cmd, words, f"{label}: {path}"))
    return errors


# ── Frontmatter and CLI references ──────────────────────────────────────────


def test_plugin_ships_exactly_the_four_skills() -> None:
    assert {p.parent.name for p in _skill_files()} == SKILL_NAMES


@pytest.mark.parametrize("name", sorted(SKILL_NAMES))
def test_skill_frontmatter(name: str) -> None:
    meta = _frontmatter((SKILLS / name / "SKILL.md").read_text(encoding="utf-8"))
    assert meta.get("name") == name
    assert isinstance(meta.get("description"), str) and meta["description"].strip()


@pytest.mark.parametrize("name", sorted(SKILL_NAMES))
def test_skill_cli_references_exist(name: str) -> None:
    path = SKILLS / name / "SKILL.md"
    text = path.read_text(encoding="utf-8")
    assert stale_cli_refs(text, f"{name}/SKILL.md") == []


def test_plugin_markdown_cli_references_exist() -> None:
    for path in [PLUGIN / "README.md", ATLAS_TABLE]:
        assert stale_cli_refs(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT))) == []


def test_checker_names_file_and_stale_reference() -> None:
    text = "Run `ziran audit . --sarifx out.sarif` then\n```bash\nziran scann --dry-run\n```\n"
    text += "and `ziran scan --coverage quick` but not prose: ziran is great.\n"
    text += "`ziran scan --phases reconnaissance trust_building` and `ziran ci r.json && "
    text += "ziran poc r.json --format=pdf`\n"
    assert stale_cli_refs(text, "x/SKILL.md") == [
        "x/SKILL.md: ziran scann: no such command",
        "x/SKILL.md: ziran audit --sarifx: no such option",
        "x/SKILL.md: ziran scan --coverage quick: not one of "
        "['essential', 'standard', 'comprehensive']",
        "x/SKILL.md: ziran scan: unexpected extra argument trust_building",
        "x/SKILL.md: ziran poc --format pdf: not one of ['python', 'curl', 'markdown', 'all']",
    ]


def test_checker_walks_command_groups() -> None:
    assert stale_cli_refs("`ziran cache clear`", "x") == []
    assert stale_cli_refs("`ziran cache clear --nope`", "x") == [
        "x: ziran cache clear --nope: no such option"
    ]


# ── GitHub Action snippet ───────────────────────────────────────────────────


def _action_steps(node: Any) -> list[dict[str, Any]]:
    if isinstance(node, dict):
        found = [node] if str(node.get("uses", "")).startswith("taoq-ai/ziran@") else []
        return found + [s for v in node.values() for s in _action_steps(v)]
    if isinstance(node, list):
        return [s for v in node for s in _action_steps(v)]
    return []


def test_audit_skill_action_snippet_uses_declared_inputs() -> None:
    inputs = set(yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))["inputs"])
    text = (SKILLS / "audit-agents" / "SKILL.md").read_text(encoding="utf-8")
    steps = [s for b in _yaml_blocks(text) for s in _action_steps(b)]
    assert steps, "audit-agents must carry a taoq-ai/ziran GitHub Action snippet"
    for step in steps:
        keys = set(step.get("with", {}))
        assert {"command", "path", "baseline"} <= keys
        assert keys <= inputs, f"undeclared action inputs: {sorted(keys - inputs)}"
        assert step["with"]["command"] == "audit"


# ── ATLAS table ─────────────────────────────────────────────────────────────


def _table_chain_types() -> set[str]:
    types: set[str] = set()
    for line in ATLAS_TABLE.read_text(encoding="utf-8").splitlines():
        cells = line.split("|")
        if line.startswith("|") and len(cells) > 3 and ATLAS_ID.search(cells[2]):
            types.update(re.findall(r"`([a-z0-9_]+)`", cells[1]))
    return types


def test_atlas_table_covers_every_chain_type() -> None:
    patterns = (KNOWLEDGE_GRAPH / "chain_patterns.yaml").read_text(encoding="utf-8")
    analyzer = (KNOWLEDGE_GRAPH / "chain_analyzer.py").read_text(encoding="utf-8")
    types = {p["type"] for p in yaml.safe_load(patterns)["patterns"]}
    types |= set(re.findall(r'vulnerability_type="([a-z_]+)"', analyzer))  # single-tool types
    assert "unrestricted_execution" in types
    table = _table_chain_types()
    assert sorted(types - table) == [], "chain types with no ATLAS row"
    assert sorted(table - types) == [], "ATLAS rows for chain types that do not exist"


def test_every_atlas_id_in_plugin_is_known() -> None:
    known = {t.value for t in AtlasTechnique}
    cited = {
        (str(p.relative_to(ROOT)), i)
        for p in PLUGIN.rglob("*.md")
        for i in ATLAS_ID.findall(p.read_text(encoding="utf-8"))
    }
    assert cited, "the plugin cites no ATLAS technique"
    assert sorted(c for c in cited if c[1] not in known) == []


# ── Offline runs of the commands the skills give ────────────────────────────


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch) -> Any:
    for var in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    runner = CliRunner()

    def _run(*args: str) -> Result:
        return runner.invoke(cli, list(args), catch_exceptions=False)

    return _run


def test_audit_sarif_baseline_round_trip(run: Any, tmp_path: Path) -> None:
    sarif, baseline = tmp_path / "audit.sarif", tmp_path / "ziran-baseline.json"
    first = run(
        "audit", str(VULNERABLE_PLUGIN), "--sarif", str(sarif), "--write-baseline", str(baseline)
    )
    assert first.exit_code != 2, first.output
    assert sarif.is_file() and baseline.is_file()
    second = run("audit", str(VULNERABLE_PLUGIN), "--baseline", str(baseline))
    assert second.exit_code == 0, second.output


def test_triage_commands_parse_and_accept_skill_suppressions(run: Any, tmp_path: Path) -> None:
    result = str(SAMPLE_RESULT)
    report = run("report", result, "--format", "json")
    assert report.exit_code != 2, report.output

    ci_flags = ["--no-github-annotations", "--no-github-summary"]
    empty = tmp_path / "empty.yaml"
    empty.write_text("version: 1\nentries: []\n", encoding="utf-8")
    bootstrap = run("ci", result, "--suppressions", str(empty), *ci_flags)
    assert bootstrap.exit_code != 2, bootstrap.output
    found = re.search(r"fingerprint=([0-9a-f]{64}) content_hash=([0-9a-f]{64})", bootstrap.output)
    assert found, bootstrap.output

    text = (SKILLS / "triage-findings" / "SKILL.md").read_text(encoding="utf-8")
    template = next(b for b in _yaml_blocks(text) if isinstance(b, dict) and b.get("entries"))
    entry = template["entries"][0]
    entry["fingerprint"], entry["content_hash"] = found.groups()
    if "expires" in entry:
        entry["expires"] = (date.today() + timedelta(days=30)).isoformat()
    suppressions = tmp_path / "suppressions.yaml"
    suppressions.write_text(yaml.safe_dump(template), encoding="utf-8")

    sarif = tmp_path / "ci.sarif"
    gated = run("ci", result, "--sarif", str(sarif), "--suppressions", str(suppressions), *ci_flags)
    assert gated.exit_code != 2, gated.output
    assert "Error loading suppressions" not in gated.output
    assert "suppressed 1" in gated.output
    assert sarif.is_file()

    policy = run("export-policy", "--result", result, "--format", "rego", "--out", str(tmp_path))
    assert policy.exit_code != 2, policy.output
    poc = run("poc", result, "-o", str(tmp_path / "pocs"))
    assert poc.exit_code != 2, poc.output


def test_scan_dry_run_offline(run: Any, tmp_path: Path) -> None:
    dry = run("scan", "--target", str(TARGET_LOCAL), "--dry-run", "-o", str(tmp_path))
    assert dry.exit_code == 0, dry.output


# ── Manifests (claude CLI optional) ─────────────────────────────────────────


@pytest.mark.skipif(shutil.which("claude") is None, reason="claude CLI not installed")
@pytest.mark.parametrize("target", [".", "plugins/ziran"])
def test_claude_plugin_validate_strict(target: str) -> None:
    proc = subprocess.run(
        ["claude", "plugin", "validate", "--strict", target],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
