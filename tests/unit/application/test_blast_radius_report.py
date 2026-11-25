"""Blast radius slice 2: data tags, the report sections and SARIF properties (spec 091)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from tests.conftest import MockAgentAdapter
from tests.unit.application.test_blast_radius import (
    CALLS,
    HTTP,
    READ,
    _attack,
    _build,
    _flat,
    _multi_agent,
)
from ziran.application.agent_scanner.result_builder import ResultBuilder
from ziran.application.agent_scanner.structure_import import import_adapter_structure
from ziran.application.cicd.sarif import generate_sarif
from ziran.application.detectors.thresholds import DetectorThresholds
from ziran.application.knowledge_graph.blast_radius import blast_radius
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph, EdgeType
from ziran.domain.entities.capability import (
    AgentCapability,
    BlastRadius,
    BlastRadiusConfig,
    CapabilityType,
    DangerousChain,
    DataTag,
)
from ziran.domain.entities.phase import CampaignResult
from ziran.infrastructure.config.detectors import DetectorConfigError, load_detector_thresholds
from ziran.interfaces.cli.html_report import build_html_report
from ziran.interfaces.cli.main import cli
from ziran.interfaces.cli.reports import ReportGenerator, _md_code

if TYPE_CHECKING:
    from pathlib import Path

PII = DataTag(data_class="pii", records=1200)


def _tagged(graph: Any, **tags: DataTag) -> Any:
    graph.blast_radius_config = BlastRadiusConfig(tags=tags)
    return graph


async def _scan(calls: tuple[dict[str, Any], ...] = CALLS, **tags: DataTag) -> Any:
    graph = _tagged(await _flat("read_file", "http_request"), **tags)
    return _build(graph, [_attack(*calls)])


@pytest.mark.unit
class TestTags:
    async def test_tag_on_the_source_given_exactly(self) -> None:
        result, chains = await _scan(sensitive_data=PII)
        (chain,) = [c for c in chains if c.vulnerability_type == "data_exfiltration"]
        assert chain.blast_radius.demonstrated.tags == {"sensitive_data": PII}
        assert chain.blast_radius.reachable.tags == {}
        stored = result.blast_radius[chain.tools[-1]]["demonstrated"]["tags"]
        assert stored == {"sensitive_data": {"data_class": "pii", "records": 1200, "owner": None}}

    async def test_no_tags_no_class_and_no_count(self) -> None:
        result, chains = await _scan()
        for radius in result.blast_radius.values():
            assert radius["demonstrated"]["tags"] == radius["reachable"]["tags"] == {}
        assert chains

    async def test_untouched_tag_is_reachable(self) -> None:
        _, chains = await _scan(({"name": "get_weather"},), sensitive_data=PII)
        (chain,) = [c for c in chains if c.vulnerability_type == "data_exfiltration"]
        assert chain.blast_radius.reachable.tags == {"sensitive_data": PII}
        assert chain.blast_radius.demonstrated.tags == {}

    async def test_a_source_tool_is_tagged_by_name(self) -> None:
        secret = DataTag(data_class="secret", owner="platform")
        graph = await _flat("read_file", "http_request")
        radius = blast_radius(graph, [HTTP], tags={"read_file": secret})
        assert radius.reachable.tags == {READ: secret}

    async def test_the_id_wins_over_the_name(self) -> None:
        graph = await _flat("read_file", "http_request")
        tags = {"read_file": PII, READ: DataTag(data_class="financial")}
        assert blast_radius(graph, [HTTP], tags=tags).reachable.tags == {READ: tags[READ]}
        flipped = dict(reversed(tags.items()))
        assert blast_radius(graph, [HTTP], tags=flipped).reachable.tags == {READ: tags[READ]}

    async def test_unreached_and_removed_nodes_are_not_tagged(self) -> None:
        graph = await _flat("read_file", "http_request")
        tags = {"elsewhere": PII, READ: PII}
        assert blast_radius(graph, [HTTP], tags=tags).reachable.tags == {READ: PII}
        assert blast_radius(graph, [HTTP], remove=[READ], tags=tags).reachable.tags == {}

    def test_downstream_agent_tagged_holder_not(self) -> None:
        radius = blast_radius(_multi_agent(), ["tool_search_docs"], tags={"a": PII, "b": PII})
        assert radius.reachable.tags == {"b": PII}  # a holds the start tool
        assert radius.demonstrated.tags == {}

    async def test_external_override_from_config(self) -> None:
        graph = await _flat("read_file", "http_request")
        graph.blast_radius_config = BlastRadiusConfig(external={"http_request": False})
        _, chains = _build(graph, [_attack(*CALLS)])
        (chain,) = [c for c in chains if c.vulnerability_type == "data_exfiltration"]
        assert chain.blast_radius.demonstrated.egress == [HTTP]
        assert chain.blast_radius.demonstrated.external == []


@pytest.mark.unit
class TestUnreachedTags:
    async def test_tag_on_a_tool_outside_every_chain_is_named(self) -> None:
        graph = _tagged(await _flat("get_weather"), get_weather=PII)
        result, chains = _build(graph, [_attack(*CALLS)])
        assert chains == []
        assert len(result.warnings) == 1
        assert "get_weather" in result.warnings[0]
        page = build_html_report(result.model_dump(mode="json"), {"nodes": [], "edges": []})
        assert "Warning: " in page and "get_weather" in page
        assert f"> **Warning:** {result.warnings[0]}" in _markdown(result)

    async def test_reached_tags_are_not_named(self) -> None:
        result, _ = await _scan(sensitive_data=PII, read_file=PII, sensitve_data=PII)
        (warning,) = result.warnings
        assert "sensitve_data" in warning  # a mistyped id
        assert "sensitive_data" not in warning and "read_file" not in warning

    async def test_reachable_but_not_demonstrated_tag_is_not_named(self) -> None:
        result, chains = await _scan(({"name": "get_weather"},), sensitive_data=PII)
        (chain,) = [c for c in chains if c.vulnerability_type == "data_exfiltration"]
        assert chain.blast_radius.reachable.tags == {"sensitive_data": PII}
        assert result.warnings == []

    async def test_unreached_tags_are_sorted(self) -> None:
        names = ["f_tag", "e_tag", "d_tag", "c_tag", "b_tag", "a_tag"]  # set order is random
        result, _ = await _scan(**dict.fromkeys(names, PII))
        (warning,) = result.warnings
        assert warning.endswith(": " + ", ".join(sorted(names)))

    async def test_follows_the_graph_warnings(self) -> None:
        graph = _tagged(await _flat("get_weather"), elsewhere=PII)
        graph.warnings.append("skipped analysis")
        result, _ = _build(graph, [_attack(*CALLS)])
        assert result.warnings[0] == "skipped analysis"
        assert len(result.warnings) == 2 and "elsewhere" in result.warnings[1]
        assert graph.warnings == ["skipped analysis"]

    async def test_no_tags_no_warning(self) -> None:
        result, _ = await _scan()
        assert result.warnings == []
        assert "warnings" not in result.metadata


@pytest.mark.unit
class TestConfig:
    def test_section_loads(self, tmp_path: Path) -> None:
        cfg = tmp_path / "detectors.yaml"
        cfg.write_text(
            "blast_radius:\n  tags:\n    read_file: {data_class: pii, records: 1200, owner: crm}\n"
            "  external:\n    upload_report: true\n"
        )
        section = load_detector_thresholds(cfg).blast_radius
        assert section.tags == {"read_file": DataTag(data_class="pii", records=1200, owner="crm")}
        assert section.external == {"upload_report": True}

    def test_default_is_empty(self) -> None:
        assert DetectorThresholds().blast_radius == BlastRadiusConfig()
        assert BlastRadiusConfig().tags == BlastRadiusConfig().external == {}

    @pytest.mark.parametrize(
        "body",
        [
            "tags: {a: {data_class: medical}}",
            "tags: {a: {data_class: pii, records: -1}}",
            "tags: {a: {data_class: pii, records: true}}",
            "tags: {a: {data_class: pii, records: 1.5}}",
            "tags: {a: {records: 3}}",
            "tags: {a: {data_class: pii, rows: 3}}",
            "external: {a: 'yes'}",
            "external: {a: 1}",
            "labels: {}",
        ],
    )
    def test_bad_section_names_the_field(self, tmp_path: Path, body: str) -> None:
        cfg = tmp_path / "detectors.yaml"
        cfg.write_text(f"blast_radius: {{{body}}}\n")
        with pytest.raises(DetectorConfigError, match="blast_radius"):
            load_detector_thresholds(cfg)

    def test_scan_hands_the_section_to_the_graph(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import MagicMock

        from tests.unit.test_trifecta import _result as scan_result

        monkeypatch.chdir(tmp_path)
        (tmp_path / "agent.py").write_text("agent_executor = None\n")
        (tmp_path / ".ziran").mkdir()
        detectors = tmp_path / ".ziran" / "detectors.yaml"
        detectors.write_text("blast_radius:\n  tags:\n    read_file: {data_class: pii}\n")
        monkeypatch.setattr("ziran.interfaces.cli.main.load_agent_adapter", MagicMock())
        run = MagicMock()
        run.run.return_value = scan_result([])
        monkeypatch.setattr("ziran.interfaces.cli.main.asyncio", run)
        scanner_cls = MagicMock()
        monkeypatch.setattr("ziran.interfaces.cli.main.AgentScanner", scanner_cls)
        args = ["scan", "--framework", "langchain", "--agent-path", "agent.py", "--output", "out"]
        result = CliRunner().invoke(cli, args)
        assert result.exit_code == 0, result.output
        config = scanner_cls.return_value.graph.blast_radius_config
        assert config == BlastRadiusConfig(tags={"read_file": DataTag(data_class="pii")})

        detectors.write_text("blast_radius:\n  tags:\n    read_file: {data_class: medical}\n")
        result = CliRunner().invoke(cli, args)
        assert result.exit_code == 0, result.output
        assert "blast_radius not read" in result.stderr
        assert scanner_cls.return_value.graph.blast_radius_config == BlastRadiusConfig()


HOSTILE = "tool_x`|<script>alert(1)</script>*_[a](b)\n#"


def _result(chains: list[dict[str, Any]], radii: dict[str, Any], **kw: Any) -> CampaignResult:
    return CampaignResult(
        campaign_id="c",
        target_agent="t",
        phases_executed=[],
        total_vulnerabilities=0,
        final_trust_score=1.0,
        success=True,
        dangerous_tool_chains=chains,
        blast_radius=radii,
        **kw,
    )


def _chain(*tools: str, vt: str = "data_exfiltration") -> dict[str, Any]:
    return {"tools": list(tools), "risk_level": "high", "vulnerability_type": vt}


def _radius(**parts: dict[str, Any]) -> dict[str, Any]:
    return BlastRadius.model_validate(parts).model_dump(mode="json")


SHOWN = _radius(
    demonstrated={
        "data_sources": ["sensitive_data"],
        "egress": [HTTP],
        "external": [HTTP],
        "counts": {"data_sources": 1, "egress": 1, "external": 1},
        "tags": {"sensitive_data": {"data_class": "pii", "records": 1200}},
    },
    reachable={
        "exec": ["tool_shell"],
        "agents": ["billing"],
        "counts": {"exec": 1, "agents": 1},
        "tags": {"tool_shell": {"data_class": "secret", "owner": "ops"}},
    },
)


async def _scanned() -> CampaignResult:
    result, _ = await _scan(sensitive_data=PII)
    return result


def _markdown(result: CampaignResult) -> str:
    return ReportGenerator.__new__(ReportGenerator)._format_markdown(result)


def _section(text: str, start: str, end: str) -> str:
    return text[text.index(start) : text.index(end, text.index(start))]


@pytest.mark.unit
class TestMarkdown:
    async def test_section_from_a_scan(self) -> None:
        text = _markdown(await _scanned())
        assert "### Blast radius" in text
        assert f"#### Chains ending at `{HTTP}` (2 chains)\n" in text  # pair and trifecta

    def test_parts_apart_external_and_tags(self) -> None:
        result = _result([_chain(READ, HTTP), _chain("a", HTTP, vt="rce")], {HTTP: SHOWN})
        text = _markdown(result)
        block = _section(text, f"#### Chains ending at `{HTTP}` (2 chains)", "\n---\n")
        shown = _section(block, "**Demonstrated**", "**Reachable**")
        reach = block[block.index("**Reachable**") :]
        assert f"- External egress: yes: `{HTTP}`" in shown
        assert f"- Egress tools: `{HTTP}`" in shown
        assert "- Data sources (a tool that can reach it ran, not proof that data was read): " in (
            shown
        )
        assert "- Tags: `sensitive_data` (pii, 1200 records)" in shown
        assert "tool_shell" not in shown and "billing" not in shown
        assert "- Exec tools: `tool_shell`" in reach and "- Downstream agents: `billing`" in reach
        assert "- Tags: `tool_shell` (secret, owner `ops`)" in reach
        assert "- External egress: no" in reach and "sensitive_data" not in reach
        assert "not proof" not in reach

    def test_reachable_data_source_is_not_worded_as_run(self) -> None:
        radius = _radius(reachable={"data_sources": ["db"], "counts": {"data_sources": 1}})
        text = _markdown(_result([_chain("a", "b")], {"b": radius}))
        assert "- Data sources: `db`" in text

    def test_more_than_listed(self) -> None:
        radius = _radius(reachable={"exec": ["t0"], "counts": {"exec": 14}})
        assert "- Exec tools: `t0` and 13 more" in _markdown(
            _result([_chain("a", "t0")], {"t0": radius})
        )
        radius = _radius(reachable={"exec": ["t0"], "counts": {"exec": 1}})
        assert "- Exec tools: `t0`\n" in _markdown(_result([_chain("a", "t0")], {"t0": radius}))
        radius = _radius(reachable={"exec": ["t0"]})  # no counts: nothing more claimed
        assert "- Exec tools: `t0`\n" in _markdown(_result([_chain("a", "t0")], {"t0": radius}))

    def test_empty_owner_is_not_rendered(self) -> None:
        radius = _radius(reachable={"tags": {"db": {"data_class": "pii", "owner": ""}}})
        text = _markdown(_result([_chain("a", "b")], {"b": radius}))
        assert "- Tags: `db` (pii)\n" in text

    def test_zero_records_and_no_owner(self) -> None:
        radius = _radius(reachable={"tags": {"db": {"data_class": "financial", "records": 0}}})
        text = _markdown(_result([_chain("a", "b")], {"b": radius}))
        assert "- Tags: `db` (financial, 0 records)\n" in text

    def test_hostile_ids_are_code_spans(self) -> None:
        radius = _radius(reachable={"exec": [HOSTILE], "counts": {"exec": 1}})
        text = _markdown(_result([_chain("a", HOSTILE)], {HOSTILE: radius}))
        span = "``tool_x`|<script>alert(1)</script>*_[a](b)\\n#``"
        assert f"#### Chains ending at {span} (1 chain)\n" in text
        assert f"- Exec tools: {span}\n" in text
        assert "\n#\n" not in text

    @pytest.mark.parametrize(
        ("raw", "span"),
        [
            ("`a", "`` `a ``"),
            ("a`", "`` a` ``"),
            ("a``b", "```a``b```"),
            ("a`b``c", "```a`b``c```"),  # the longest run sets the fence, not the shortest
            ("a``b`c", "```a``b`c```"),
            ("a", "`a`"),
            ("", "` `"),  # an empty span would fuse with a later backtick run
            ("\n", "`\\n`"),  # a control shows escaped, never raw
        ],
    )
    def test_code_span_fences(self, raw: str, span: str) -> None:
        assert _md_code(raw) == span

    def test_control_ids_stay_on_one_table_row(self) -> None:
        tool = "send\nmail\u202e|x\x1b[2J"
        radius = _radius(reachable={"tags": {tool: {"data_class": "pii", "owner": "o\r\x9bwn"}}})
        result = _result([_chain("read", tool)], {tool: radius}, critical_paths=[["read", tool]])
        text = _markdown(result)

        table = _section(text, "| Risk | Type | Tools | Description |", "\n\n")
        assert len(table.splitlines()) == 3  # header, rule and one chain row
        shown = "send\\nmail\\u202e|x\\x1b[2J"
        cell = shown.replace("|", "\\|")  # a table cell escapes |
        assert f"| `read → {cell}` |" in table
        assert f"1. `read → {shown}`\n" in text
        assert "owner `o\\r\\x9bwn`" in text
        assert not [c for c in text if c != "\n" and not c.isprintable() and c != "\ufe0f"]

    def test_mixed_runs_stay_inside_the_span(self) -> None:
        raw = "a`b``[click](http://evil.example)<img src=x>`c"
        radius = _radius(reachable={"exec": [raw], "counts": {"exec": 1}})
        text = _markdown(_result([_chain("a", raw)], {raw: radius}))
        assert f"- Exec tools: ```{raw}```\n" in text
        assert f"#### Chains ending at ```{raw}``` (1 chain)\n" in text

    def test_one_block_per_last_tool(self) -> None:
        chains = [_chain(f"s{i}", HTTP) for i in range(50)] + [_chain("a", "t0")]
        text = _markdown(_result(chains, {HTTP: SHOWN, "t0": _radius()}))
        assert text.count("#### Chains ending at") == 2
        assert text.index(f"`{HTTP}` (50 chains)") < text.index(
            "#### Chains ending at `t0` (1 chain)"
        )
        assert text.count("**Demonstrated**") == 2

    def test_chain_without_tools_or_radius(self) -> None:
        text = _markdown(_result([_chain(), _chain("a", "b")], {HTTP: SHOWN}))
        assert "Blast radius" not in text

    def test_no_radius_renders_as_before(self) -> None:
        assert "Blast radius" not in _markdown(_result([_chain(READ, HTTP)], {}))


@pytest.mark.unit
class TestHtml:
    async def test_section_from_a_scan(self) -> None:
        result = await _scanned()
        page = build_html_report(result.model_dump(mode="json"), {"nodes": [], "edges": []})
        assert '<div class="section-title">Blast radius</div>' in page
        assert f"Chains ending at {HTTP}" in page

    def test_parts_apart_external_and_tags(self) -> None:
        data = _result([_chain(READ, HTTP)], {HTTP: SHOWN}).model_dump(mode="json")
        page = build_html_report(data, {"nodes": [], "edges": []})
        section = _section(page, "Blast radius</div>", "<!-- Attack Paths -->")
        shown = _section(section, "<strong>Demonstrated", "<strong>Reachable")
        reach = section[section.index("<strong>Reachable") :]
        assert "External egress: yes" in shown and "sensitive_data (pii, 1200 records)" in shown
        assert "a tool that can reach it ran" in shown and "tool_shell" not in shown
        assert "External egress: no" in reach and "tool_shell (secret, owner ops)" in reach
        assert "(1 chain)" in section

    def test_hostile_ids_are_escaped(self) -> None:
        radius = _radius(reachable={"exec": [HOSTILE], "counts": {"exec": 1}})
        data = _result([_chain("a", HOSTILE)], {HOSTILE: radius}).model_dump(mode="json")
        page = build_html_report(data, {"nodes": [], "edges": []})
        section = _section(page, "Blast radius</div>", "<!-- Attack Paths -->")
        assert "<script>" not in section and "&lt;script&gt;" in section

    def test_control_ids_are_escaped_on_one_line(self) -> None:
        tool = "send\nmail\u202e<b>"
        radius = _radius(reachable={"exec": [tool], "counts": {"exec": 1}})
        result = _result([_chain("read", tool)], {tool: radius}, critical_paths=[["read", tool]])
        page = build_html_report(result.model_dump(mode="json"), {"nodes": [], "edges": []})
        section = _section(page, "Blast radius</div>", "<!-- Attack Paths -->")

        assert "send\\nmail\\u202e&lt;b&gt;" in section
        assert "\u202e" not in page and "send\nmail" not in page

    def test_no_radius_is_byte_identical(self) -> None:
        data = _result([_chain(READ, HTTP)], {}).model_dump(mode="json")
        page = build_html_report(data, {"nodes": [], "edges": []})
        data.pop("blast_radius")
        assert page == build_html_report(data, {"nodes": [], "edges": []})
        assert "Blast radius" not in page


def _chain_rows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [r for r in doc["runs"][0]["results"] if "tools" in r.get("properties", {})]


@pytest.mark.unit
class TestSarif:
    async def test_summary_from_a_scan(self) -> None:
        result = await _scanned()
        rows = {tuple(r["properties"]["tools"]): r for r in _chain_rows(generate_sarif(result))}
        summary = rows[(READ, HTTP)]["properties"]["blast_radius"]
        assert summary["external"] is True
        assert summary["data_classes"] == ["pii"]
        assert summary["demonstrated"]["external"] == summary["demonstrated"]["egress"] == 1

    def test_counts_external_and_classes(self) -> None:
        doc = generate_sarif(_result([_chain(READ, HTTP)], {HTTP: SHOWN}))
        (row,) = _chain_rows(doc)
        assert row["properties"]["blast_radius"] == {
            "demonstrated": SHOWN["demonstrated"]["counts"],
            "reachable": SHOWN["reachable"]["counts"],
            "external": True,
            "data_classes": ["pii", "secret"],
        }
        assert json.loads(json.dumps(doc)) == doc

    @pytest.mark.parametrize(
        ("part", "external"), [("demonstrated", True), ("reachable", True), (None, False)]
    )
    def test_external_from_either_part(self, part: str | None, external: bool) -> None:
        parts = {part: {"external": [HTTP], "counts": {"external": 1}}} if part else {}
        doc = generate_sarif(_result([_chain(READ, HTTP)], {HTTP: _radius(**parts)}))
        assert _chain_rows(doc)[0]["properties"]["blast_radius"]["external"] is external

    def test_classes_sorted_and_unique(self) -> None:
        classes = ["source_code", "secret", "pii", "financial"]
        tag = {f"n{i}": {"data_class": c} for i, c in enumerate(classes)}
        radius = _radius(
            demonstrated={"tags": tag}, reachable={"tags": {"z": {"data_class": "financial"}}}
        )
        doc = generate_sarif(_result([_chain(READ, HTTP)], {HTTP: radius}))
        summary = _chain_rows(doc)[0]["properties"]["blast_radius"]
        assert summary["data_classes"] == ["financial", "pii", "secret", "source_code"]

    def test_no_radius_or_no_tools_keeps_properties(self) -> None:
        doc = generate_sarif(_result([_chain(), _chain("a", "b")], {HTTP: SHOWN}))
        assert [r["properties"] for r in _chain_rows(doc)] == [
            {"tools": [], "vulnerability_type": "data_exfiltration", "severity": "high"},
            {"tools": ["a", "b"], "vulnerability_type": "data_exfiltration", "severity": "high"},
        ]

    def test_attack_results_byte_identical(self) -> None:
        attack = {
            "vector_id": "v1",
            "vector_name": "V1",
            "category": "prompt_injection",
            "severity": "high",
            "successful": True,
            "evidence": {"tool_calls": [{"name": "read_file"}]},
            "owasp_mapping": ["LLM01"],
        }
        with_radius = _result([_chain(READ, HTTP)], {HTTP: SHOWN}, attack_results=[attack])
        without = _result([_chain(READ, HTTP)], {}, attack_results=[attack])
        a, b = generate_sarif(with_radius), generate_sarif(without)
        assert json.dumps(a["runs"][0]["results"][0]) == json.dumps(b["runs"][0]["results"][0])
        assert a["runs"][0]["tool"] == b["runs"][0]["tool"]

    def test_malformed_radius_names_the_field(self) -> None:
        bad = {HTTP: {"demonstrated": {"tags": {"x": {"data_class": "medical"}}}}}
        with pytest.raises(ValidationError, match="data_class"):
            generate_sarif(_result([_chain(READ, HTTP)], bad))


@pytest.mark.unit
def test_report_command_rejects_a_bad_radius(tmp_path: Path) -> None:
    bad = {HTTP: {"demonstrated": {"tags": {"x": {"data_class": "medical"}}}}}
    saved = tmp_path / "result.json"
    saved.write_text(_result([_chain(READ, HTTP)], bad).model_dump_json())
    run = CliRunner().invoke(cli, ["report", str(saved), "--format", "markdown"])
    assert run.exit_code == 1
    assert isinstance(run.exception, SystemExit)
    assert "data_class" in run.output
    assert not list(tmp_path.glob("*.md"))


SECRET = DataTag(data_class="secret")
_KIND = {"vulnerability_type": "data_exfiltration", "exploit_description": "x"}


async def _probed(**tags: DataTag) -> Any:
    """An agent as remote-probe discovery maps it (spec 102): only the dangerous tool links to
    sensitive_data, and no edge reaches the reading tools."""
    caps = [
        AgentCapability(id="probe_read_inbox", name="read_inbox", type=CapabilityType.SKILL),
        AgentCapability(id="probe_get_weather", name="get_weather", type=CapabilityType.SKILL),
        AgentCapability(
            id="probe_send_email", name="send_email", type=CapabilityType.TOOL, dangerous=True
        ),
    ]
    graph = AttackKnowledgeGraph()
    for c in caps:
        graph.add_capability(c.id, c)
    graph.add_data_source("sensitive_data")
    graph.add_edge("probe_send_email", "sensitive_data", EdgeType.ACCESSES_DATA)
    await import_adapter_structure(MockAgentAdapter(), graph, caps)
    return _tagged(graph, **tags)


def _classes(radius: BlastRadius) -> set[str]:
    tags = radius.demonstrated.tags | radius.reachable.tags
    return {t.data_class for t in tags.values()}


@pytest.mark.unit
class TestSourceTools:
    """A chain's data classes include what its source tools reach (spec 102)."""

    async def test_tagged_source_tool_shows_on_the_chain(self) -> None:
        result, chains = _build(await _probed(probe_read_inbox=PII), [])
        (chain,) = [c for c in chains if c.tools == ["probe_read_inbox", "probe_send_email"]]
        assert chain.blast_radius.reachable.tags == {"probe_read_inbox": PII}
        stored = result.blast_radius["probe_send_email"]["reachable"]["tags"]
        assert set(stored) == {"probe_read_inbox"}

    async def test_shared_sensitive_data_gains_no_false_class(self) -> None:
        tags = {"sensitive_data": SECRET, "probe_get_weather": PII}  # no chain holds get_weather
        _, chains = _build(await _probed(**tags), [])
        assert chains
        for chain in chains:
            assert _classes(chain.blast_radius) == {"secret"}

    async def test_file_to_http_chain_still_reads_only_secret(self) -> None:
        _, chains = await _scan(sensitive_data=SECRET)
        (chain,) = [c for c in chains if c.vulnerability_type == "data_exfiltration"]
        assert chain.tools == [READ, HTTP]
        assert chain.blast_radius.demonstrated.tags == {"sensitive_data": SECRET}
        assert _classes(chain.blast_radius) == {"secret"}

    async def test_tagged_source_tool_is_demonstrated_when_called(self) -> None:
        graph = await _probed(probe_read_inbox=PII)
        _, chains = _build(graph, [_attack({"name": "read_inbox"})])
        (chain,) = [c for c in chains if c.tools[0] == "probe_read_inbox"]
        assert chain.blast_radius.demonstrated.tags == {"probe_read_inbox": PII}

    async def test_chains_sharing_a_last_tool_share_one_walk(self) -> None:
        graph = await _probed(probe_read_inbox=PII, probe_get_weather=SECRET)
        chains = [
            DangerousChain(tools=[a, "probe_send_email"], risk_level="high", **_KIND)
            for a in ("probe_read_inbox", "probe_get_weather")
        ]
        radii = ResultBuilder(graph, "probed")._fill_blast_radius(chains, [])
        assert set(radii) == {"probe_send_email"}
        for chain in chains:
            assert chain.blast_radius is radii["probe_send_email"]
            assert _classes(chain.blast_radius) == {"pii", "secret"}
