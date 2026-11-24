"""`ziran ci` gates a ziran SARIF file like the CampaignResult it came from (spec 093)."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from tests.unit.test_cicd_suppressions import (
    TODAY,
    _attack,
    _campaign,
    _ci,
    _entries_for,
    _entry,
    _write_result,
    _write_sup,
)
from ziran.application.cicd.gate import QualityGate
from ziran.application.cicd.sarif import (
    campaign_from_sarif,
    generate_audit_sarif,
    generate_sarif,
)
from ziran.domain.entities.ci import QualityGateConfig, SeverityThresholds, SuppressionFile
from ziran.domain.entities.phase import (
    UNMEASURED_METADATA_KEY,
    WARNINGS_METADATA_KEY,
    CampaignResult,
    PhaseResult,
    ScanPhase,
)

if TYPE_CHECKING:
    from ziran.domain.entities.ci import GateResult

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample_campaign_result.json"


def _chain(tools: tuple[str, ...], risk: str, vt: str, **kw: Any) -> dict[str, Any]:
    return {"tools": list(tools), "risk_level": risk, "vulnerability_type": vt, **kw}


def _mixed() -> CampaignResult:
    result = _campaign(
        attacks=[
            _attack("v1"),
            _attack("v2", "data_exfiltration", "high"),
            _attack("v3", severity="info"),
            _attack("v4", severity="low", successful=False),
            _attack("v2", "data_exfiltration", "high"),
        ],
        chains=[
            _chain(("read_file", "http_request"), "critical", "data_exfiltration"),
            _chain(("a", "b"), "high", "rce", graph_path=["a", "b"]),
            _chain(("c", "d"), "medium", "lethal_trifecta"),
            _chain(("e", "f"), "severe", "privilege_escalation"),
        ],
        critical_paths=[["x", "v1"], ["y", "a", "b"], [], ["a", "b"]],
        phase_vulns=["v1", "other"],
        success=True,
    )
    return result.model_copy(update={"final_trust_score": 0.42})


def _cases() -> list[CampaignResult]:
    return [
        _campaign(),
        _mixed(),
        CampaignResult.model_validate_json(FIXTURE.read_text()),
    ]


def _configs() -> list[QualityGateConfig]:
    return [
        QualityGateConfig(),
        QualityGateConfig(min_trust_score=0.8, fail_on_policy_violation=False),
        QualityGateConfig(
            max_critical_findings=5,
            severity_thresholds=SeverityThresholds(high=0, medium=0, low=0),
        ),
    ]


def _suppressions(result: CampaignResult) -> list[SuppressionFile | None]:
    findings = QualityGate._findings(result)
    some = [_entry(f) for f in findings[::2]]
    if findings:
        some.append(_entry(findings[-1], content_hash="0" * 64))
    return [None, SuppressionFile(version=1, entries=some), _entries_for(result)]


def _comparable(gate: GateResult) -> dict[str, Any]:
    # a finding's index points into attack_results, which keeps failed attacks only in the JSON
    return gate.model_dump(exclude={"findings": {"__all__": {"index"}}})


def _round_trip(result: CampaignResult) -> CampaignResult:
    return campaign_from_sarif(json.loads(json.dumps(generate_sarif(result))))


def _with_unmeasured(result: CampaignResult, *ids: str) -> CampaignResult:
    return result.model_copy(update={"metadata": {UNMEASURED_METADATA_KEY: list(ids)}})


def _suppressed_mixed(**kw: Any) -> tuple[CampaignResult, QualityGateConfig, SuppressionFile]:
    result = _mixed()
    entries = [_entry(f, **kw) for f in QualityGate._findings(result)]
    return result, QualityGateConfig(), SuppressionFile(version=1, entries=entries)


_RULE_CASES: dict[str, Any] = {
    "min_trust_score": lambda: (_mixed(), QualityGateConfig(min_trust_score=0.5), None),
    "max_critical_findings": lambda: (_mixed(), QualityGateConfig(), None),
    "severity_threshold_high": lambda: (
        _mixed(),
        QualityGateConfig(severity_thresholds=SeverityThresholds(critical=-1, high=2)),
        None,
    ),
    "severity_threshold_medium": lambda: (
        _mixed(),
        QualityGateConfig(severity_thresholds=SeverityThresholds(medium=0)),
        None,
    ),
    "nothing_measured": lambda: (
        _with_unmeasured(_campaign(attacks=[_attack("v1", successful=False)] * 2), "v1", "v2"),
        QualityGateConfig(),
        None,
    ),
    "policy_violation": lambda: (
        _mixed(),
        QualityGateConfig(
            max_critical_findings=-1, severity_thresholds=SeverityThresholds(critical=-1)
        ),
        None,
    ),
    "suppression_regressed": lambda: _suppressed_mixed(content_hash="0" * 64),
    "suppression_expired": lambda: _suppressed_mixed(expires=date(2025, 1, 1)),
}


@pytest.mark.unit
class TestRunProperties:
    def test_generate_sarif_writes_the_gate_inputs(self) -> None:
        props = generate_sarif(_mixed())["runs"][0]["properties"]["ziran"]
        assert props["target_agent"] == "test_agent"
        assert props["final_trust_score"] == 0.42
        assert props["success"] is True
        assert props["critical_paths"] == [["x", "v1"], ["y", "a", "b"], [], ["a", "b"]]
        assert (props["schema"], props["attack_count"]) == (1, 5)

    def test_each_result_carries_its_severity(self) -> None:
        rows = generate_sarif(_mixed())["runs"][0]["results"]
        sev = [r["properties"]["severity"] for r in rows]
        assert sev == ["critical", "high", "info", "high", "critical", "high", "medium", "severe"]
        assert rows[5]["properties"]["graph_path"] == ["a", "b"]


@pytest.mark.unit
class TestGateParity:
    @pytest.mark.parametrize("case", range(3))
    @pytest.mark.parametrize("config", range(3))
    def test_same_gate_result(self, case: int, config: int) -> None:
        result = _cases()[case]
        gate = QualityGate(_configs()[config])
        for sup in _suppressions(result):
            want = gate.evaluate(result, sup, today=TODAY)
            got = gate.evaluate(_round_trip(result), sup, today=TODAY)
            assert _comparable(got) == _comparable(want)

    def test_mixed_case_fails_on_every_rule(self) -> None:
        result = _mixed()
        cfg = QualityGateConfig(min_trust_score=0.8)
        got = QualityGate(cfg).evaluate(_round_trip(result))
        assert [v.rule for v in got.violations] == [
            "min_trust_score",
            "max_critical_findings",
            "severity_threshold_critical",
            "policy_violation",
        ]
        assert (got.finding_counts.critical, got.finding_counts.high) == (2, 3)

    @pytest.mark.parametrize("rule", sorted(_RULE_CASES))
    def test_each_rule_fires_alike(self, rule: str) -> None:
        result, config, sup = _RULE_CASES[rule]()
        want = QualityGate(config).evaluate(result, sup, today=TODAY)
        got = QualityGate(config).evaluate(_round_trip(result), sup, today=TODAY)
        assert rule in [v.rule for v in want.violations]
        assert _comparable(got) == _comparable(want)

    @pytest.mark.parametrize(("attacks", "unmeasured"), [(4, 1), (10, 2), (3, 3), (1, 2)])
    def test_unmeasured_with_failed_attacks(self, attacks: int, unmeasured: int) -> None:
        failed = [_attack(f"v{i}", successful=False) for i in range(attacks)]
        result = _campaign(attacks=failed).model_copy(
            update={"metadata": {UNMEASURED_METADATA_KEY: [f"v{i}" for i in range(unmeasured)]}}
        )
        want = QualityGate().evaluate(result)
        assert _comparable(QualityGate().evaluate(_round_trip(result))) == _comparable(want)
        assert ("nothing_measured" in [v.rule for v in want.violations]) is (unmeasured >= attacks)

    def test_rebuilt_chain_keeps_graph_path(self) -> None:
        chains = _round_trip(_mixed()).dangerous_tool_chains
        assert [c.get("graph_path") for c in chains] == [None, ["a", "b"], None, None]

    def test_repeated_phase_merges_its_vulnerabilities(self) -> None:
        phase = next(iter(ScanPhase))
        rows = [
            PhaseResult(
                phase=phase,
                success=True,
                trust_score=0.8,
                duration_seconds=0.0,
                vulnerabilities_found=[v],
            )
            for v in ("v1", "v2")
        ]
        result = _campaign().model_copy(update={"phases_executed": rows})
        assert _round_trip(result).all_vulnerabilities == ["v1", "v2"]

    def test_schema_defaults_to_1(self) -> None:
        doc = generate_sarif(_mixed())
        del doc["runs"][0]["properties"]["ziran"]["schema"]
        assert campaign_from_sarif(doc).final_trust_score == 0.42

    @pytest.mark.parametrize("count", ["5", 5.0, True, -1, 3, 1_000_001, None])
    def test_attack_count_refused(self, count: Any) -> None:
        doc = generate_sarif(_mixed())  # lists 4 successful attacks
        doc["runs"][0]["properties"]["ziran"]["attack_count"] = count
        with pytest.raises(ValueError, match="attack_count"):
            campaign_from_sarif(doc)

    def test_attack_count_at_the_cap(self) -> None:
        doc = generate_sarif(_mixed())
        doc["runs"][0]["properties"]["ziran"]["attack_count"] = 1_000_000
        assert len(campaign_from_sarif(doc).attack_results) == 1_000_000

    def test_attack_count_missing_is_named(self) -> None:
        doc = generate_sarif(_mixed())
        del doc["runs"][0]["properties"]["ziran"]["attack_count"]
        with pytest.raises(ValueError, match=r"lacks attack_count;"):
            campaign_from_sarif(doc)

    def test_metadata_survives(self) -> None:
        result = _campaign().model_copy(
            update={
                "metadata": {UNMEASURED_METADATA_KEY: ["v9"], WARNINGS_METADATA_KEY: ["capped"]}
            }
        )
        back = _round_trip(result)
        assert (back.unmeasured_vectors, back.warnings) == (["v9"], ["capped"])


@pytest.fixture
def ci_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    return tmp_path


def _outputs(path: Path) -> str:
    text = path.read_text()
    path.unlink()
    return text


@pytest.mark.unit
class TestCiCommand:
    @pytest.mark.parametrize("case", range(3))
    def test_json_and_sarif_gate_alike(self, ci_env: Path, case: int) -> None:
        result = _cases()[case]
        if case == 1:
            _write_sup(ci_env / ".ziran" / "suppressions.yaml", _suppressions(result)[1])
        json_file = _write_result(ci_env / "r.json", result)
        sarif = ci_env / "r.sarif"
        sarif.write_text(json.dumps(generate_sarif(result)))

        a = _ci(json_file, "--no-github-annotations")
        out_a = _outputs(ci_env / "out.txt")
        b = _ci(str(sarif), "--no-github-annotations")
        out_b = _outputs(ci_env / "out.txt")
        assert (b.exit_code, out_b) == (a.exit_code, out_a), b.output
        assert "Error" not in b.output

    def test_foreign_sarif_names_the_missing_properties(self, ci_env: Path) -> None:
        doc = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "OtherTool"}}, "results": []}],
        }
        (ci_env / "other.sarif").write_text(json.dumps(doc))
        out = _ci("other.sarif")
        assert out.exit_code == 1
        assert "Traceback" not in out.output
        for name in ("target_agent", "final_trust_score", "success"):
            assert name in out.output

    def test_two_runs_refused_even_with_a_clean_first_run(self, ci_env: Path) -> None:
        clean = generate_sarif(_campaign().model_copy(update={"final_trust_score": 1.0}))
        dirty = generate_sarif(_mixed())
        clean["runs"].append(dirty["runs"][0])
        (ci_env / "merged.sarif").write_text(json.dumps(clean))
        out = _ci("merged.sarif")
        assert out.exit_code == 1
        assert "expected one SARIF run" in out.output

    def test_sarif_input_skips_sarif_output(self, ci_env: Path) -> None:
        sarif = ci_env / "r.sarif"
        sarif.write_text(json.dumps(generate_sarif(_mixed())))
        before = sarif.read_text()
        out = _ci(str(sarif), "--sarif", str(sarif))
        assert out.exit_code == 1
        assert "--sarif skipped" in out.output
        assert sarif.read_text() == before

    def test_sarif_input_skips_policy(self, ci_env: Path) -> None:
        (ci_env / "r.sarif").write_text(json.dumps(generate_sarif(_mixed())))
        policy = Path(__file__).parents[2] / "ziran/application/policy/default_policy.yaml"
        out = _ci("r.sarif", "--policy", str(policy), "--no-github-annotations")
        assert out.exit_code == 1
        assert "--policy skipped" in out.output
        assert "policy evaluation failed" not in out.output

    def test_unknown_schema_refused(self, ci_env: Path) -> None:
        doc = generate_sarif(_campaign())
        doc["runs"][0]["properties"]["ziran"]["schema"] = 2
        (ci_env / "s.sarif").write_text(json.dumps(doc))
        out = _ci("s.sarif")
        assert out.exit_code == 1
        assert "schema 2" in out.output

    def test_wrong_type_names_the_array(self, ci_env: Path) -> None:
        doc = generate_sarif(_mixed())
        doc["runs"][0]["results"] = {"x": 1}
        (ci_env / "t.sarif").write_text(json.dumps(doc))
        out = _ci("t.sarif")
        assert out.exit_code == 1
        assert "results must be an array" in out.output

    def test_driver_version_is_the_package_version(self) -> None:
        from ziran import __version__

        assert generate_sarif(_campaign())["runs"][0]["tool"]["driver"]["version"] == __version__

    def test_audit_sarif_is_not_a_scan(self, ci_env: Path) -> None:
        (ci_env / "audit.sarif").write_text(json.dumps(generate_audit_sarif([])))
        out = _ci("audit.sarif")
        assert out.exit_code == 1
        assert "properties.ziran" in out.output

    def test_partial_properties_name_only_the_missing(self, ci_env: Path) -> None:
        doc = generate_sarif(_campaign())
        del doc["runs"][0]["properties"]["ziran"]["success"]
        (ci_env / "p.sarif").write_text(json.dumps(doc))
        out = _ci("p.sarif")
        assert out.exit_code == 1
        assert "success" in out.output and "target_agent" not in out.output

    @pytest.mark.parametrize(
        "doc",
        [
            {"runs": []},
            {"runs": "x"},
            {"runs": [{}, {}]},
            {"runs": [{"properties": {"ziran": "x"}}]},
            {"runs": [{"properties": "x"}]},
        ],
    )
    def test_malformed_envelope_exits_1(self, ci_env: Path, doc: dict[str, Any]) -> None:
        (ci_env / "bad.sarif").write_text(json.dumps(doc))
        out = _ci("bad.sarif")
        assert out.exit_code == 1
        assert "Error loading result" in out.output
        assert out.exception is None or isinstance(out.exception, SystemExit)

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda run: run.update(results=["x"]),
            lambda run: run.update(results="x"),
            lambda run: run["results"][0].pop("ruleId"),
            lambda run: run["results"][0].update(properties="x"),
            lambda run: run["tool"]["driver"].update(rules="x"),
            lambda run: run["properties"]["ziran"].update(final_trust_score=2.0),
            lambda run: run["properties"]["ziran"].update(critical_paths="x"),
        ],
    )
    def test_malformed_body_exits_1(self, ci_env: Path, mutate: Any) -> None:
        doc = generate_sarif(_mixed())
        mutate(doc["runs"][0])
        (ci_env / "bad.sarif").write_text(json.dumps(doc))
        out = _ci("bad.sarif")
        assert out.exit_code == 1
        assert "Error loading result" in out.output
        assert out.exception is None or isinstance(out.exception, SystemExit)
