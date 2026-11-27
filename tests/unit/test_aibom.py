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
        fs, notes, search = (
            refs["mcp:aibom-plugin/filesystem"],
            refs["mcp:aibom-plugin/notes"],
            refs["mcp:aibom-plugin/search"],
        )
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
        researcher, helper = (
            refs["agent:aibom-plugin/researcher"],
            refs["agent:aibom-plugin/helper"],
        )
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
        assert deps["agent:aibom-plugin/researcher"] == [
            "model:sonnet",
            "mcp:aibom-plugin/filesystem",
        ]
        assert deps["agent:aibom-plugin/helper"] == []

    def test_cve_matches_are_in_triage(self, bom: dict[str, Any]) -> None:
        vulns = {v["id"]: v for v in bom["vulnerabilities"]}
        assert "CVE-2025-53109" in vulns
        v = vulns["CVE-2025-53109"]
        assert v["affects"] == [{"ref": "agent:aibom-plugin/researcher"}]
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
        assert {
            "mcp:aibom-plugin/filesystem",
            "mcp:aibom-plugin/notes",
            "mcp:aibom-plugin/search",
        } <= set(_by_ref(bom))

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
    agent = _by_ref(bom)["agent:p/a"]
    assert _props(agent, "ziran:model") == ["unknown"]
    assert _props(agent, "ziran:tools") == []  # an empty declared set is known, not inherited
    assert "version" not in bom["metadata"]["component"]


def _plugin(root: Path, servers: dict[str, Any], tools: str = "Read") -> dict[str, Any]:
    """BOM of a plugin `p` with *servers* in `.mcp.json` and one agent `a` declaring *tools*."""
    (root / ".claude-plugin").mkdir(exist_ok=True)
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "p"}))
    (root / "agents").mkdir(exist_ok=True)
    (root / "agents" / "a.md").write_text(f"---\nname: a\ntools: {tools}\n---\nx\n")
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    bom = build_aibom(load_claude_code(root))
    _assert_valid(bom)
    return bom


class TestNoLeak:
    def test_env_placeholder_is_not_expanded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ZIRAN_T_LEAK", "ENVSECRET_12345")
        bom = _plugin(
            tmp_path,
            {
                "cmd": {"command": "${ZIRAN_T_LEAK}/srv", "args": ["${ZIRAN_T_LEAK}"]},
                "web": {"type": "sse", "url": "https://h.example/${ZIRAN_T_LEAK}/sse"},
            },
        )
        assert "ENVSECRET_12345" not in json.dumps(bom)
        refs = _by_ref(bom)
        assert _props(refs["mcp:p/cmd"], "ziran:command") == ["${ZIRAN_T_LEAK}/srv"]
        assert refs["mcp:p/web"]["endpoints"] == ["https://h.example/${ZIRAN_T_LEAK}/sse"]

    @pytest.mark.parametrize(
        "args",
        [
            ["--password", "pass@123", "pkg"],
            ["--api-key", "SECRET@1.2.3"],
            ["-y", "--token", "tok==9", "pkg@1.0.0"],
            ["--flag@1.0"],  # M11: a flag is never the package, even when it looks pinned
            ["-y", "--x==2"],
        ],
    )
    def test_option_value_is_not_a_package(self, tmp_path: Path, args: list[str]) -> None:
        bom = _plugin(tmp_path, {"s": {"command": "npx", "args": args}})
        server = _by_ref(bom)["mcp:p/s"]
        assert "version" not in server
        assert _props(server, "ziran:package") == []
        assert _props(server, "ziran:version") == ["unknown"]
        for secret in ("pass", "123", "SECRET", "tok"):
            assert secret not in json.dumps(server)

    @pytest.mark.parametrize(
        ("command", "args", "package", "version"),
        [
            ("npx", ["-y", "@scope/srv@1.2.3", "--port", "1"], "@scope/srv", "1.2.3"),
            ("/usr/local/bin/npx", ["srv@2.0.0"], "srv", "2.0.0"),
            ("bunx", ["srv@1.0.0"], "srv", "1.0.0"),
            ("uvx", ["--quiet", "mcp-srv==0.4.1"], "mcp-srv", "0.4.1"),
            ("pipx", ["run", "mcp-srv==0.4.1"], "mcp-srv", "0.4.1"),
            ("pnpm", ["dlx", "srv@3.1.0"], "srv", "3.1.0"),
        ],
    )
    def test_runner_package_is_read(
        self, tmp_path: Path, command: str, args: list[str], package: str, version: str
    ) -> None:
        server = _by_ref(_plugin(tmp_path, {"s": {"command": command, "args": args}}))["mcp:p/s"]
        assert (server.get("version"), _props(server, "ziran:package")) == (version, [package])

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("node", ["srv@1.0.0"]),  # not a runner
            ("pipx", ["install", "srv==1.0.0"]),  # not `pipx run`
            ("npx", ["--registry", "r@1.0", "srv@1.0.0"]),  # an unknown runner flag
        ],
    )
    def test_no_package_outside_a_runner_shape(
        self, tmp_path: Path, command: str, args: list[str]
    ) -> None:
        server = _by_ref(_plugin(tmp_path, {"s": {"command": command, "args": args}}))["mcp:p/s"]
        assert "version" not in server
        assert _props(server, "ziran:package") == []

    def test_url_fragment_never_reaches_the_bom(self, tmp_path: Path) -> None:
        bom = _plugin(tmp_path, {"s": {"type": "http", "url": "https://h.example/mcp#token=FRAG"}})
        assert "FRAG" not in json.dumps(bom)
        assert _by_ref(bom)["mcp:p/s"]["endpoints"] == ["https://h.example/mcp"]

    def test_plugin_folder_in_a_command_reads_root(self, tmp_path: Path) -> None:
        command = f"{tmp_path.resolve()}/bin/srv"
        bom = _plugin(tmp_path, {"s": {"command": command}})
        assert _props(_by_ref(bom)["mcp:p/s"], "ziran:command") == ["${CLAUDE_PLUGIN_ROOT}/bin/srv"]


class TestGuards:
    def test_two_tools_on_one_cve_affect_the_agent_once(self, tmp_path: Path) -> None:
        tools = "mcp__filesystem__read_file, mcp__filesystem__write_file"
        bom = _plugin(tmp_path, {"filesystem": {"command": "srv"}}, tools)  # validated in _plugin
        vulns = {v["id"]: v for v in bom["vulnerabilities"]}
        assert vulns["CVE-2025-53109"]["affects"] == [{"ref": "agent:p/a"}]

    def test_tool_of_an_unconfigured_server_is_no_dependency(self, tmp_path: Path) -> None:
        bom = _plugin(tmp_path, {"s": {"command": "srv"}}, "mcp__slack__post, mcp__s__x")
        deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
        assert deps["agent:p/a"] == ["mcp:p/s"]

    def test_two_traces_of_one_agent_add_it_once(self, bom: dict[str, Any]) -> None:
        added = add_shadow(bom, [_session(agent="billing"), _session(agent="billing")])
        assert added == ["shadow-agent:billing"]
        assert [c["bom-ref"] for c in bom["components"]].count("shadow-agent:billing") == 1
        _assert_valid(bom)

    def test_plain_tool_with_underscores_is_not_a_server(self, bom: dict[str, Any]) -> None:
        assert add_shadow(bom, [_session("lookup__customer", "lookup__customer__get")]) == []
        assert bom["version"] == 1


class TestLoadBom:
    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ({"services": "x"}, "'services' must be a list of objects"),
            ({"services": None}, "'services' must be a list of objects"),
            ({"components": [1]}, "'components' must be a list of objects"),
            ({"metadata": None}, "'metadata' must be an object"),
            ({"version": "abc"}, "'version' must be a positive integer"),
            ({"services": [{"name": [1]}]}, "'services' must be a list of objects"),  # M10
            ({"metadata": {"component": {"name": 1}}}, "'metadata' must be an object"),
        ],
    )
    def test_malformed_bom_is_refused(
        self, tmp_path: Path, change: dict[str, Any], message: str
    ) -> None:
        path = tmp_path / "in.json"
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1} | change
        path.write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            load_bom(path)

    def test_not_utf8_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "in.json"
        path.write_bytes(b"\xff\xfe{")
        with pytest.raises(ValueError, match="not readable"):
            load_bom(path)

    def test_analyze_traces_refuses_a_bad_bom_before_the_report(self, tmp_path: Path) -> None:
        bom_path = tmp_path / "in.json"
        bom_path.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6", "services": "x"}')
        traces = tmp_path / "t.jsonl"
        traces.write_text("")
        out = tmp_path / "out"
        args = ["analyze-traces", "--source", "otel", "--input", str(traces), "--out", str(out)]
        args += ["--aibom", str(bom_path), "--alert", "--dry-run-alerts"]
        result = CliRunner().invoke(cli, args)
        assert result.exit_code == 2, result.output
        assert "'services' must be a list of objects" in result.output
        assert not out.exists()  # no report, no alert


class TestSkillsAndRefs:
    """Spec 135: skills in the audit BOM, plugin-prefixed refs, old refs still read."""

    @staticmethod
    def _skill(root: Path, name: str, front: str) -> None:
        folder = root / "skills" / name
        folder.mkdir(parents=True)
        (folder / "SKILL.md").write_text(f"---\nname: {name}\n{front}---\nbody\n")

    def test_audit_aibom_lists_skills_with_allowed_tools(self, tmp_path: Path) -> None:
        self._skill(tmp_path, "notes", "allowed-tools: Read, mcp__filesystem__read_file\n")
        self._skill(tmp_path, "plain", "description: no tools\n")
        _plugin(tmp_path, {"filesystem": {"command": "srv"}})
        out = tmp_path / "bom.json"
        result = CliRunner().invoke(cli, ["audit", str(tmp_path), "--aibom", str(out)])
        assert result.exit_code in (0, 1), result.output
        bom = json.loads(out.read_text(encoding="utf-8"))
        _assert_valid(bom)
        refs = _by_ref(bom)
        notes, plain = refs["skill:p/notes"], refs["skill:p/plain"]
        assert notes["type"] == "application"
        assert _props(notes, "ziran:kind") == ["skill"]
        assert _props(notes, "ziran:source") == ["skills/notes/SKILL.md:2"]
        assert _props(notes, "ziran:allowed-tool") == ["Read", "mcp__filesystem__read_file"]
        assert _props(plain, "ziran:allowed-tool") == []
        deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
        assert deps["skill:p/notes"] == ["mcp:p/filesystem"]
        vulns = {v["id"]: v for v in bom["vulnerabilities"]}
        assert {"ref": "skill:p/notes"} in vulns["CVE-2025-53109"]["affects"]

    def test_two_plugins_agents_of_one_name_get_two_refs(self, tmp_path: Path) -> None:
        refs = []
        for plugin in ("one", "two"):
            root = tmp_path / plugin
            (root / ".claude-plugin").mkdir(parents=True)
            (root / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": plugin}))
            (root / "agents").mkdir()
            (root / "agents" / "a.md").write_text("---\nname: a\ntools: Read\n---\nx\n")
            refs += [c["bom-ref"] for c in build_aibom(load_claude_code(root))["components"]]
        assert refs == ["agent:one/a", "agent:two/a"]

    def test_no_manifest_keeps_unprefixed_refs(self, tmp_path: Path) -> None:
        (tmp_path / "agents").mkdir()
        (tmp_path / "agents" / "a.md").write_text("---\nname: a\ntools: Read\n---\nx\n")
        assert [c["bom-ref"] for c in build_aibom(load_claude_code(tmp_path))["components"]] == [
            "agent:a"
        ]

    @pytest.mark.parametrize("prefix", ["", "aibom-plugin/"])
    def test_shadow_reads_old_and_new_refs(self, bom: dict[str, Any], prefix: str) -> None:
        for entry in [*bom["components"], *bom["services"]]:  # rewrite to the given ref form
            kind, _, rest = entry["bom-ref"].partition(":")
            entry["bom-ref"] = f"{kind}:{prefix}{rest.removeprefix('aibom-plugin/')}"
        added = add_shadow(
            bom,
            [_session("mcp__filesystem__read_file", "mcp__slack__post", agent="researcher")],
        )
        assert added == ["shadow-mcp:slack"]


def _caps() -> list[Any]:
    from ziran.domain.entities.capability import AgentCapability, CapabilityType

    return [
        AgentCapability(id="read_file", name="read_file", type=CapabilityType.DATA_ACCESS),
        AgentCapability(id="shell", name="shell", type=CapabilityType.TOOL, dangerous=True),
        AgentCapability(id="book", name="Book", type=CapabilityType.SKILL),
        AgentCapability(id="security_scheme_k", name="Auth: k", type=CapabilityType.PERMISSION),
    ]


SECRET_URL = "https://user:pw-fixture@agent.example.com/v1?key=query-fixture#frag-fixture"


class TestScanBom:
    """Spec 135: the scan BOM of a target config."""

    def test_openai_target_lists_model_and_tools(self) -> None:
        from ziran.application.aibom import build_scan_aibom
        from ziran.domain.entities.target import TargetConfig

        target = TargetConfig.model_validate(
            {
                "url": SECRET_URL,
                "protocol": "openai",
                "openai": {"model": "gpt-4o-mini"},
                "headers": {"X-Api-Key": "hunter2-fixture"},
            }
        )
        bom = build_scan_aibom(_caps(), source="target.yaml", target=target, protocol="openai")
        _assert_valid(bom)
        subject = bom["metadata"]["component"]
        assert (subject["bom-ref"], subject["name"]) == (
            "agent:agent.example.com",
            "agent.example.com",
        )
        assert _props(subject, "ziran:source") == ["target.yaml"]
        assert _props(subject, "ziran:protocol") == ["openai"]
        assert _props(subject, "ziran:tool") == ["read_file", "shell"]
        assert _props(subject, "ziran:skill") == ["book"]
        assert _props(subject, "ziran:model") == []
        model = _by_ref(bom)["model:gpt-4o-mini"]
        assert model["type"] == "machine-learning-model"
        deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
        assert deps["agent:agent.example.com"] == ["model:gpt-4o-mini"]
        text = json.dumps(bom)
        for secret in ("pw-fixture", "query-fixture", "frag-fixture", "hunter2-fixture", "Auth: k"):
            assert secret not in text

    def test_mcp_target_is_a_service(self) -> None:
        from ziran.application.aibom import build_scan_aibom
        from ziran.domain.entities.target import TargetConfig

        target = TargetConfig.model_validate({"url": SECRET_URL, "protocol": "mcp"})
        bom = build_scan_aibom(_caps(), source="t.yaml", target=target, protocol="mcp")
        _assert_valid(bom)
        server = _by_ref(bom)["mcp:agent.example.com"]
        assert server["endpoints"] == ["https://agent.example.com/v1"]
        assert _props(server, "ziran:version") == ["unknown"]
        assert _props(bom["metadata"]["component"], "ziran:model") == ["unknown"]
        deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
        assert deps["agent:agent.example.com"] == ["mcp:agent.example.com"]
        assert "pw-fixture" not in json.dumps(bom)

    def test_a2a_card_is_a_peer_with_its_skills(self) -> None:
        from ziran.application.aibom import build_scan_aibom
        from ziran.domain.entities.a2a import A2AAgentCard
        from ziran.domain.entities.target import TargetConfig

        card = A2AAgentCard.model_validate(
            {
                "name": "travel",
                "version": "2.1.0",
                "supportedInterfaces": [{"url": SECRET_URL}],
                "skills": [{"id": "book", "name": "Book"}, {"id": "cancel", "name": "Cancel"}],
            }
        )
        target = TargetConfig.model_validate({"url": SECRET_URL, "protocol": "a2a"})
        bom = build_scan_aibom(_caps(), source="t.yaml", target=target, protocol="a2a", card=card)
        _assert_valid(bom)
        assert bom["metadata"]["component"]["name"] == "travel"
        peer = _by_ref(bom)["a2a:travel"]
        assert peer["version"] == "2.1.0"
        assert peer["endpoints"] == ["https://agent.example.com/v1"]
        assert _props(peer, "ziran:skill") == ["book", "cancel"]
        assert "pw-fixture" not in json.dumps(bom)

    def test_cve_match_affects_the_target(self) -> None:
        from ziran.application.aibom import build_scan_aibom
        from ziran.domain.entities.capability import AgentCapability, CapabilityType

        cap = AgentCapability(
            id="mcp__filesystem__read_file",
            name="mcp__filesystem__read_file",
            type=CapabilityType.EXTERNAL_API,
        )
        bom = build_scan_aibom([cap], source="agent.py", target=None, protocol="langchain")
        _assert_valid(bom)
        assert bom["metadata"]["component"]["bom-ref"] == "agent:agent"
        vulns = {v["id"]: v for v in bom["vulnerabilities"]}
        assert vulns["CVE-2025-53109"]["affects"] == [{"ref": "agent:agent"}]

    def test_scan_cli_writes_the_bom(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from unittest.mock import MagicMock

        from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
        from ziran.domain.entities.a2a import A2AAgentCard
        from ziran.domain.entities.phase import CampaignResult
        from ziran.domain.entities.target import ProtocolType, TargetConfig

        target = TargetConfig.model_validate(
            {"url": SECRET_URL, "protocol": "auto", "openai": {"model": "gpt-4o-mini"}}
        )
        card = A2AAgentCard(name="travel", supportedInterfaces=[{"url": SECRET_URL}])
        adapter = MagicMock(protocol=ProtocolType.A2A, agent_card=card)
        monkeypatch.setattr(
            "ziran.interfaces.cli.main.load_remote_adapter", lambda *a: (adapter, target)
        )
        graph = AttackKnowledgeGraph()
        for cap in _caps():
            graph.add_capability(cap.id, cap)
        monkeypatch.setattr(
            "ziran.interfaces.cli.main.AgentScanner", MagicMock(return_value=MagicMock(graph=graph))
        )
        result = CampaignResult(
            campaign_id="c",
            target_agent="t",
            phases_executed=[],
            total_vulnerabilities=0,
            final_trust_score=1.0,
            success=False,
        )
        monkeypatch.setattr(
            "ziran.interfaces.cli.main.asyncio", MagicMock(run=MagicMock(return_value=result))
        )
        (tmp_path / "t.yaml").write_text("url: https://x.example\n")
        out = tmp_path / "bom.json"
        args = ["scan", "--target", str(tmp_path / "t.yaml"), "--output", str(tmp_path / "out")]
        run = CliRunner().invoke(cli, [*args, "--aibom", str(out)])
        assert run.exit_code == 0, run.output
        bom = json.loads(out.read_text(encoding="utf-8"))
        _assert_valid(bom)
        subject = bom["metadata"]["component"]
        assert (subject["name"], _props(subject, "ziran:protocol")) == ("travel", ["a2a"])
        assert _props(subject, "ziran:tool") == ["read_file", "shell"]
        assert {"model:gpt-4o-mini", "a2a:travel"} <= set(_by_ref(bom))
        assert "pw-fixture" not in out.read_text(encoding="utf-8")

    def test_scan_aibom_unwritable_is_a_usage_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import MagicMock

        from ziran.domain.entities.phase import CampaignResult

        monkeypatch.setattr("ziran.interfaces.cli.main.load_agent_adapter", MagicMock())
        monkeypatch.setattr("ziran.interfaces.cli.main.AgentScanner", MagicMock())
        result = CampaignResult(
            campaign_id="c",
            target_agent="t",
            phases_executed=[],
            total_vulnerabilities=0,
            final_trust_score=1.0,
            success=False,
        )
        monkeypatch.setattr(
            "ziran.interfaces.cli.main.asyncio", MagicMock(run=MagicMock(return_value=result))
        )
        agent = tmp_path / "agent.py"
        agent.write_text("x = 1\n")
        args = ["scan", "--framework", "langchain", "--agent-path", str(agent)]
        args += ["--output", str(tmp_path / "out"), "--aibom", str(tmp_path / "no" / "b.json")]
        run = CliRunner().invoke(cli, args)
        assert run.exit_code == 2, run.output
        assert "cannot write file" in run.output


def test_http_adapter_exposes_the_fetched_card() -> None:
    from unittest.mock import MagicMock

    from ziran.domain.entities.a2a import A2AAgentCard
    from ziran.domain.entities.target import TargetConfig
    from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

    adapter = HttpAgentAdapter(TargetConfig(url="https://a.example", protocol="a2a"))
    assert adapter.agent_card is None  # discovery has not run
    card = A2AAgentCard(name="travel")
    adapter._handler = MagicMock(agent_card=card)
    assert adapter.agent_card is card
