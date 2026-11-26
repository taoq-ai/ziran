"""CycloneDX 1.6 AI-BOM of a Claude Code plugin and shadow servers from traces (spec 123)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from ziran.application.aibom import add_shadow, build_aibom, load_bom
from ziran.domain.entities.trace import ToolCallEvent, TraceSession
from ziran.infrastructure.config.claude_code_plugin import load_claude_code
from ziran.interfaces.cli.main import cli

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
PLUGIN = FIXTURES / "claude_code" / "aibom_plugin"
SCHEMAS = FIXTURES / "cyclonedx"


def _validator() -> Draft7Validator:
    resources = []
    for file in SCHEMAS.glob("*.schema.json"):
        schema = json.loads(file.read_text(encoding="utf-8"))
        resource = Resource.from_contents(schema)
        resources += [(schema["$id"], resource), (file.name, resource)]
    bom_schema = json.loads((SCHEMAS / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    return Draft7Validator(bom_schema, registry=Registry().with_resources(resources))


def _assert_valid(bom: dict[str, Any]) -> None:
    errors = sorted(_validator().iter_errors(bom), key=str)
    assert not errors, [f"{list(e.absolute_path)}: {e.message}" for e in errors]


def _props(entry: dict[str, Any], name: str) -> list[str]:
    return [p["value"] for p in entry.get("properties", []) if p["name"] == name]


def _by_ref(bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {e["bom-ref"]: e for e in [*bom.get("components", []), *bom.get("services", [])]}


@pytest.fixture
def bom() -> dict[str, Any]:
    return build_aibom(load_claude_code(PLUGIN))


def _session(*tools: str, agent: str = "unknown") -> TraceSession:
    now = datetime(2026, 11, 26, tzinfo=UTC)
    return TraceSession(
        session_id="s-1",
        agent_name=agent,
        tool_calls=[ToolCallEvent(tool_name=t, timestamp=now) for t in tools],
        start_time=now,
        end_time=now,
        source="otel",
    )


class TestBuild:
    def test_validates_against_cyclonedx_1_6(self, bom: dict[str, Any]) -> None:
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"
        _assert_valid(bom)

    def test_plugin_is_the_subject(self, bom: dict[str, Any]) -> None:
        subject = bom["metadata"]["component"]
        assert (subject["name"], subject["version"]) == ("aibom-plugin", "1.4.0")
        assert _props(subject, "ziran:source") == [".claude-plugin/plugin.json"]

    def test_each_mcp_server_has_command_and_version(self, bom: dict[str, Any]) -> None:
        refs = _by_ref(bom)
        fs, notes, search = refs["mcp:filesystem"], refs["mcp:notes"], refs["mcp:search"]
        assert fs["version"] == "2025.7.1"
        assert _props(fs, "ziran:command") == ["npx"]
        assert _props(fs, "ziran:package") == ["@modelcontextprotocol/server-filesystem"]
        assert _props(fs, "ziran:transport") == ["stdio"]
        assert "version" not in notes
        assert _props(notes, "ziran:version") == ["unknown"]
        assert _props(notes, "ziran:command") == ["python3"]
        assert search["endpoints"] == ["https://mcp.example.com/mcp"]
        assert _props(search, "ziran:version") == ["unknown"]
        assert all(_props(s, "ziran:source") == [".mcp.json"] for s in (fs, notes, search))

    def test_no_secret_reaches_the_bom(self, bom: dict[str, Any]) -> None:
        text = json.dumps(bom)
        for secret in ("hunter2-fixture", "env-fixture-value", "pw-fixture", "query-fixture"):
            assert secret not in text

    def test_agents_models_and_unknowns(self, bom: dict[str, Any]) -> None:
        refs = _by_ref(bom)
        researcher, helper = refs["agent:researcher"], refs["agent:helper"]
        assert researcher["type"] == "application"
        assert _props(researcher, "ziran:source") == ["agents/researcher.md:2"]
        assert _props(researcher, "ziran:tool") == [
            "Read",
            "WebFetch",
            "mcp__filesystem__read_file",
        ]
        model = refs["model:sonnet"]
        assert model["type"] == "machine-learning-model"
        assert _props(model, "ziran:source") == ["agents/researcher.md:4"]
        assert _props(helper, "ziran:model") == ["unknown"]
        assert _props(helper, "ziran:tools") == ["unknown"]
        assert _props(helper, "ziran:tool") == []

    def test_dependencies_link_agent_to_model_and_server(self, bom: dict[str, Any]) -> None:
        deps = {d["ref"]: d.get("dependsOn", []) for d in bom["dependencies"]}
        assert deps["agent:researcher"] == ["model:sonnet", "mcp:filesystem"]
        assert deps["agent:helper"] == []

    def test_cve_matches_are_in_triage(self, bom: dict[str, Any]) -> None:
        vulns = {v["id"]: v for v in bom["vulnerabilities"]}
        assert "CVE-2025-53109" in vulns
        v = vulns["CVE-2025-53109"]
        assert v["affects"] == [{"ref": "agent:researcher"}]
        assert v["analysis"]["state"] == "in_triage"

    def test_bom_refs_are_unique(self, bom: dict[str, Any]) -> None:
        refs = [e["bom-ref"] for e in [*bom["components"], *bom["services"]]]
        refs += [v["bom-ref"] for v in bom["vulnerabilities"]]
        assert len(refs) == len(set(refs))


class TestShadow:
    def test_server_missing_from_bom_is_shadow(self, bom: dict[str, Any]) -> None:
        added = add_shadow(
            bom,
            [
                _session(
                    "Read",
                    "mcp__filesystem__read_file",
                    "mcp__plugin_aibom-plugin_notes__list",
                    "mcp__slack__post_message",
                    "mcp__slack__read_channel",
                )
            ],
        )
        assert added == ["shadow-mcp:slack"]
        slack = _by_ref(bom)["shadow-mcp:slack"]
        assert _props(slack, "ziran:shadow") == ["true"]
        assert _props(slack, "ziran:source") == ["trace otel session s-1"]
        assert bom["version"] == 2
        _assert_valid(bom)

    def test_agent_missing_from_bom_is_shadow(self, bom: dict[str, Any]) -> None:
        added = add_shadow(
            bom,
            [_session(agent="unknown"), _session(agent="researcher"), _session(agent="billing")],
        )
        assert added == ["shadow-agent:billing"]
        assert _by_ref(bom)["shadow-agent:billing"]["type"] == "application"

    def test_load_bom_refuses_other_documents(self, tmp_path: Path) -> None:
        path = tmp_path / "x.json"
        for doc in (
            "[]",
            '{"bomFormat": "SPDX"}',
            '{"bomFormat": "CycloneDX", "specVersion": "1.4"}',
        ):
            path.write_text(doc)
            with pytest.raises(ValueError, match=r"CycloneDX 1\.6"):
                load_bom(path)
        path.write_text("{not json")
        with pytest.raises(ValueError, match="invalid JSON"):
            load_bom(path)


class TestCli:
    def test_audit_writes_aibom(self, tmp_path: Path) -> None:
        out = tmp_path / "aibom.json"
        result = CliRunner().invoke(
            cli, ["audit", str(PLUGIN), "--format", "json", "--aibom", str(out)]
        )
        assert result.exit_code == 1, result.output  # findings still fail the audit
        json.loads(result.stdout)  # stdout stays the findings JSON
        bom = json.loads(out.read_text(encoding="utf-8"))
        _assert_valid(bom)
        assert {"mcp:filesystem", "mcp:notes", "mcp:search"} <= set(_by_ref(bom))

    def test_audit_aibom_needs_claude_code(self, tmp_path: Path) -> None:
        src = tmp_path / "agent.py"
        src.write_text("x = 1\n")
        result = CliRunner().invoke(cli, ["audit", str(src), "--aibom", str(tmp_path / "b.json")])
        assert result.exit_code == 2
        assert "no Claude Code" in result.output

    def test_analyze_traces_marks_shadow(self, tmp_path: Path) -> None:
        bom_path = tmp_path / "in.json"
        bom_path.write_text(json.dumps(build_aibom(load_claude_code(PLUGIN))), encoding="utf-8")
        span = {
            "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
            "spanId": "0000000000000001",
            "name": "mcp__slack__post_message",
            "startTimeUnixNano": "1760000000000000000",
            "endTimeUnixNano": "1760000000250000000",
            "attributes": [
                {"key": "session.id", "value": {"stringValue": "cc-1"}},
                {"key": "gen_ai.tool.name", "value": {"stringValue": "mcp__slack__post_message"}},
            ],
        }
        traces = tmp_path / "t.jsonl"
        traces.write_text(json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]}))
        result = CliRunner().invoke(
            cli,
            [
                "analyze-traces",
                "--source",
                "otel",
                "--input",
                str(traces),
                "--out",
                str(tmp_path / "out"),
                "--aibom",
                str(bom_path),
            ],
        )
        assert result.exit_code == 0, result.output
        bom = json.loads((tmp_path / "out" / "aibom.json").read_text(encoding="utf-8"))
        _assert_valid(bom)
        assert _props(_by_ref(bom)["shadow-mcp:slack"], "ziran:shadow") == ["true"]


def test_duplicate_server_and_inherited_model(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "p", "mcpServers": "./extra.json"})
    )
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "a.md").write_text("---\nname: a\nmodel: inherit\ntools:\n---\nx\n")
    (tmp_path / ".mcp.json").write_text(json.dumps({"s": {"command": "first"}}))
    (tmp_path / "extra.json").write_text(json.dumps({"s": {"command": "second"}}))
    bom = build_aibom(load_claude_code(tmp_path))
    _assert_valid(bom)
    assert [_props(s, "ziran:command") for s in bom["services"]] == [["first"]]
    agent = _by_ref(bom)["agent:a"]
    assert _props(agent, "ziran:model") == ["unknown"]
    assert _props(agent, "ziran:tools") == []  # an empty declared set is known, not inherited
    assert "version" not in bom["metadata"]["component"]
