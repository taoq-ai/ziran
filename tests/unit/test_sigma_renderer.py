"""Sigma detection rules from proven chains (spec 120)."""

from __future__ import annotations

import copy
import time
from typing import Any

import pytest
import yaml

from tests.unit.application.test_blast_radius import CALLS, _attack, _build, _flat
from ziran.application.policy_export.export_service import ExportService
from ziran.domain.entities.capability import DangerousChain
from ziran.domain.entities.ci import chain_fingerprint
from ziran.domain.entities.phase import CampaignResult
from ziran.domain.sigma import sigma_matches, sigma_schema_errors
from ziran.infrastructure.policy_renderers.sigma_renderer import SigmaRenderer

_TRACE = "ab" * 16

_RESULT: dict[str, Any] = {
    "campaign_id": "c1",
    "target_agent": "test-agent",
    "phases_executed": [],
    "total_vulnerabilities": 1,
    "final_trust_score": 0.3,
    "success": True,
    "attack_results": [
        {
            "vector_id": "exfil_file_http",
            "vector_name": "File exfiltration",
            "category": "data_exfiltration",
            "severity": "critical",
            "successful": True,
            "evidence": {
                "tool_calls": [
                    {"tool": "read_file", "input": {"path": "/etc/passwd"}},
                    {"name": "http_request", "input": {"url": "https://x.test"}},
                ]
            },
            "owasp_mapping": ["LLM02"],
            "owasp_agentic_mapping": ["ASI02"],
            "atlas_mapping": ["AML.T0086"],
            "probe_markers": [
                {
                    "probe_id": "c1/exfil_file_http/1",
                    "trace_id": _TRACE,
                    "sent_at": "2026-11-26T00:00:00Z",
                }
            ],
        }
    ],
    "dangerous_tool_chains": [
        {
            "tools": ["read_file", "http_request"],
            "risk_level": "critical",
            "vulnerability_type": "data_exfiltration",
            "exploit_description": "File read then exfil via HTTP",
        },
        {
            "tools": ["sql_query", "http_request"],
            "risk_level": "high",
            "vulnerability_type": "sql_to_rce",
            "exploit_description": "No recorded attack ran this one",
        },
    ],
}


def _export(raw: dict[str, Any], **kwargs: Any) -> list[Any]:
    result = CampaignResult.model_validate(raw)
    return ExportService(SigmaRenderer(result, **kwargs)).export(result, severity_floor="low")


def _span(tool: str, t: float, session: str = "s1", trace: str = "0" * 32) -> dict[str, Any]:
    return {
        "time": t,
        "trace_id": trace,
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": tool,
        "gen_ai.conversation.id": session,
    }


@pytest.mark.unit
class TestSigmaExport:
    def test_proven_chain_validates_and_correlation_names_rules_and_fingerprint(self) -> None:
        policy = _export(_RESULT)[0]
        assert not policy.skipped, policy.skip_reason
        assert policy.format.value == "sigma"
        docs = list(yaml.safe_load_all(policy.content))
        assert len(docs) == 3
        for doc in docs:
            assert sigma_schema_errors(doc) == []
        steps, corr = docs[:2], docs[2]
        assert [s["detection"]["selection"]["gen_ai.tool.name"] for s in steps] == [
            ["read_file"],
            ["http_request"],
        ]
        assert all(
            s["detection"]["selection"]["gen_ai.operation.name"] == "execute_tool" for s in steps
        )
        assert corr["correlation"]["type"] == "temporal"
        assert corr["correlation"]["rules"] == [s["name"] for s in steps]
        assert corr["correlation"]["group-by"] == ["gen_ai.conversation.id"]
        fingerprint = chain_fingerprint("test-agent", "data_exfiltration")
        assert f"ziran fingerprint {fingerprint}" in corr["references"]
        assert "ziran finding ZIRAN-c1-000" in corr["references"]
        assert "ziran vector exfil_file_http" in corr["references"]
        assert corr["level"] == "critical"
        assert {"atlas.aml.t0086", "owasp.llm02", "owasp.asi02"} <= set(corr["tags"])
        assert "temporal_ordered" in corr["description"]
        assert corr["falsepositives"]
        assert all(s["level"] == "informational" for s in steps)

    def test_self_check_matches_recorded_session_not_read_file_only(self) -> None:
        content = _export(_RESULT)[0].content
        assert sigma_matches(content, [_span("read_file", 0), _span("http_request", 5)])
        assert not sigma_matches(content, [_span("read_file", 0), _span("read_file", 5)])
        # two sessions, one tool each: no session holds the chain
        assert not sigma_matches(
            content, [_span("read_file", 0, "s1"), _span("http_request", 5, "s2")]
        )
        # outside the timespan
        assert not sigma_matches(content, [_span("read_file", 0), _span("http_request", 7200)])
        assert "# Self-check: matched the recorded calls of exfil_file_http" in content

    def test_malformed_evidence_is_unproven_not_a_crash(self) -> None:
        raw = copy.deepcopy(_RESULT)
        raw["attack_results"][0]["evidence"] = "not a mapping"
        raw["attack_results"].append({"vector_id": "v2", "evidence": {"tool_calls": "x"}})
        assert all(p.skipped for p in _export(raw))
        # a call with no name proves no tool, not even an unnamed one
        raw = copy.deepcopy(_RESULT)
        raw["attack_results"][0]["evidence"]["tool_calls"].append({"input": {}})
        raw["dangerous_tool_chains"][0]["tools"] = ["", "http_request"]
        assert _export(raw)[0].skipped

    def test_unproven_chain_is_skipped_with_reason(self) -> None:
        policy = _export(_RESULT)[1]
        assert policy.skipped
        assert policy.skip_reason is not None
        assert "no recorded attack" in policy.skip_reason

    def test_exclude_probes_filters_scan_trace_ids(self) -> None:
        content = _export(_RESULT, exclude_probes=True)[0].content
        docs = list(yaml.safe_load_all(content))
        assert docs[0]["detection"]["filter_ziran_probe"] == {"trace_id": [_TRACE]}
        assert docs[0]["detection"]["condition"] == "selection and not filter_ziran_probe"
        assert not sigma_matches(
            content, [_span("read_file", 0, trace=_TRACE), _span("http_request", 5, trace=_TRACE)]
        )
        assert sigma_matches(content, [_span("read_file", 0), _span("http_request", 5)])
        plain = _export(_RESULT)[0].content
        assert "filter_ziran_probe" not in plain

    def test_ids_are_stable_and_unique(self) -> None:
        first, second = _export(_RESULT)[0].content, _export(_RESULT)[0].content
        assert first == second
        ids = [d["id"] for d in yaml.safe_load_all(first)]
        assert len(set(ids)) == 3

    def test_tool_prefix_matches_bare_name(self) -> None:
        raw = copy.deepcopy(_RESULT)
        raw["dangerous_tool_chains"][0]["tools"] = ["tool_read_file", "tool_http_request"]
        content = _export(raw)[0].content
        assert sigma_matches(content, [_span("read_file", 0), _span("http_request", 1)])
        assert sigma_matches(content, [_span("tool_read_file", 0), _span("HTTP_REQUEST", 1)])

    def test_one_tool_chain_has_no_correlation_and_carries_level(self) -> None:
        raw = copy.deepcopy(_RESULT)
        raw["dangerous_tool_chains"] = [
            {
                "tools": ["read_file"],
                "risk_level": "high",
                "vulnerability_type": "unrestricted_execution",
                "exploit_description": "Unscoped shell",
            }
        ]
        policy = _export(raw)[0]
        docs = list(yaml.safe_load_all(policy.content))
        assert len(docs) == 1
        assert docs[0]["level"] == "high"
        assert sigma_matches(policy.content, [_span("read_file", 0)])
        assert not sigma_matches(policy.content, [_span("write_file", 0)])

    def test_hostile_tool_name_stays_one_literal_value(self) -> None:
        name = "x*\n---\ntitle: evil\n# ?"
        raw = copy.deepcopy(_RESULT)
        raw["attack_results"][0]["evidence"]["tool_calls"][0]["tool"] = name
        raw["dangerous_tool_chains"][0]["tools"] = [name, "http_request"]
        policy = _export(raw)[0]
        assert not policy.skipped, policy.skip_reason
        docs = list(yaml.safe_load_all(policy.content))
        assert len(docs) == 3
        assert all(sigma_schema_errors(d) == [] for d in docs)
        comments = [line for line in policy.content.splitlines() if line.startswith("#")]
        assert all("title: evil" not in line or "\\n" in line for line in comments)
        # "*" and "?" are escaped: a name they would match as wildcards does not match
        other = "xZZ\n---\ntitle: evil\n# !"
        assert not sigma_matches(policy.content, [_span(other, 0), _span("http_request", 1)])
        assert sigma_matches(policy.content, [_span(name, 0), _span("http_request", 1)])


@pytest.mark.unit
class TestHostileInput:
    @pytest.mark.parametrize("trace", ["a*", "*" * 25 + "a", "AB" * 16, "ab" * 15, ""])
    def test_probe_trace_id_not_32_hex_skips_with_reason(self, trace: str) -> None:
        raw = copy.deepcopy(_RESULT)
        raw["attack_results"][0]["probe_markers"][0]["trace_id"] = trace
        policies = _export(raw, exclude_probes=True)
        assert all(p.skipped for p in policies)
        assert all("trace id" in str(p.skip_reason) for p in policies)
        assert not _export(raw)[0].skipped  # no filter asked, no trace id read

    def test_wildcard_value_matching_is_linear(self) -> None:
        rule = {"detection": {"selection": {"f": "*" * 25 + "a"}, "condition": "selection"}}
        start = time.perf_counter()
        assert not sigma_matches(yaml.safe_dump(rule), [{"f": "b" * 2000}])
        assert sigma_matches(yaml.safe_dump(rule), [{"f": "b" * 2000 + "A"}])
        assert time.perf_counter() - start < 1.0

    def test_lone_surrogate_tool_name_exports(self) -> None:
        name = "read\ud800file"
        raw = copy.deepcopy(_RESULT)
        raw["attack_results"][0]["evidence"]["tool_calls"][0]["tool"] = name
        raw["dangerous_tool_chains"][0]["tools"] = [name, "http_request"]
        policy = _export(raw)[0]
        assert not policy.skipped, policy.skip_reason
        policy.content.encode("utf-8")  # writable as the CLI writes it

    def test_long_backslash_tool_name_is_one_literal(self) -> None:
        name = "a\\b" * 100  # 300 characters, a backslash in each step
        raw = copy.deepcopy(_RESULT)
        raw["attack_results"][0]["evidence"]["tool_calls"][0]["tool"] = name
        raw["dangerous_tool_chains"][0]["tools"] = [name, "http_request"]
        policy = _export(raw)[0]
        assert not policy.skipped, policy.skip_reason
        assert sigma_matches(policy.content, [_span(name, 0), _span("http_request", 1)])
        assert not sigma_matches(policy.content, [_span("ab" * 100, 0), _span("http_request", 1)])

    def test_same_type_chains_get_distinct_ids(self) -> None:
        raw = copy.deepcopy(_RESULT)
        raw["attack_results"][0]["evidence"]["tool_calls"].append({"tool": "read_db"})
        raw["dangerous_tool_chains"][1] = {
            **raw["dangerous_tool_chains"][0],
            "tools": ["read_db", "http_request"],
        }
        policies = _export(raw)
        assert not any(p.skipped for p in policies)
        ids = [d["id"] for p in policies for d in yaml.safe_load_all(p.content)]
        assert len(ids) == 6
        assert len(set(ids)) == 6

    def test_tag_with_trailing_newline_is_dropped(self) -> None:
        raw = copy.deepcopy(_RESULT)
        raw["attack_results"][0]["atlas_mapping"] = ["AML.T0086\n"]
        docs = list(yaml.safe_load_all(_export(raw)[0].content))
        assert all(not t.startswith("atlas.") for d in docs for t in d["tags"])


@pytest.mark.unit
class TestFromAScan:
    async def test_result_builder_output_exports_a_matching_rule(self) -> None:
        """A real scan result (tool ids with ``tool_``, OpenAI-shaped calls) through the export."""
        result, _ = _build(await _flat("read_file", "http_request"), [_attack(*CALLS)])
        policies = ExportService(SigmaRenderer(result)).export(result, severity_floor="low")
        exfil = [p for p in policies if p.tool_chain == ["tool_read_file", "tool_http_request"]]
        assert exfil
        assert not exfil[0].skipped, exfil[0].skip_reason
        content = exfil[0].content
        assert sigma_matches(content, [_span("read_file", 0), _span("http_request", 1)])
        assert not sigma_matches(content, [_span("read_file", 0)])


@pytest.mark.unit
class TestSelfCheck:
    def _parts(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        content = _export(_RESULT)[0].content
        return list(yaml.safe_load_all(content)), _RESULT["attack_results"][0]

    def test_refuses_a_level_sigma_does_not_name(self) -> None:
        result = CampaignResult.model_validate(_RESULT)
        chain = DangerousChain.model_validate(
            {**_RESULT["dangerous_tool_chains"][0], "risk_level": "severe"}
        )
        policy = SigmaRenderer(result).render(chain, "ZIRAN-c1-000")
        assert policy.skipped
        assert policy.skip_reason is not None
        assert "self-check failed" in policy.skip_reason
        assert "level" in policy.skip_reason

    def test_refuses_a_rule_that_misses_the_recorded_calls(self) -> None:
        docs, attack = self._parts()
        docs[1]["detection"]["selection"]["gen_ai.tool.name"] = ["send_email"]
        failure = SigmaRenderer._self_check(yaml.safe_dump_all(docs), docs, attack)
        assert "does not match the recorded calls" in failure

    def test_refuses_a_correlation_that_fires_without_the_last_tool(self) -> None:
        docs, attack = self._parts()
        docs[2]["correlation"]["rules"] = [docs[0]["name"]]
        failure = SigmaRenderer._self_check(yaml.safe_dump_all(docs), docs, attack)
        assert "without the chain's last tool" in failure


@pytest.mark.unit
class TestSigmaSchemaErrors:
    def test_flags_missing_and_bad_fields(self) -> None:
        bad = {
            "title": "t" * 300,
            "id": "not-a-uuid",
            "level": "severe",
            "tags": ["Bad Tag"],
            "logsource": {},
            "detection": {"selection": {"a": 1}},
        }
        errors = sigma_schema_errors(bad)
        for word in ("title", "id", "level", "tags", "logsource", "condition"):
            assert any(word in e for e in errors), (word, errors)

    def test_flags_temporal_without_group_by(self) -> None:
        bad = {"title": "t", "correlation": {"type": "temporal", "rules": ["a"], "timespan": "1h"}}
        assert any("group-by" in e for e in sigma_schema_errors(bad))
