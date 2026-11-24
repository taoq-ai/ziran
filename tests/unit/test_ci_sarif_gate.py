"""`ziran ci` gates a ziran SARIF file like the CampaignResult it came from (spec 093)."""

from __future__ import annotations

import json
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
        critical_paths=[["x", "v1"], ["y", "a", "b"], []],
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


@pytest.mark.unit
class TestRunProperties:
    def test_generate_sarif_writes_the_gate_inputs(self) -> None:
        props = generate_sarif(_mixed())["runs"][0]["properties"]["ziran"]
        assert props["target_agent"] == "test_agent"
        assert props["final_trust_score"] == 0.42
        assert props["success"] is True
        assert props["critical_paths"] == [["x", "v1"], ["y", "a", "b"], []]

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

    def test_sarif_out_of_a_sarif_gates_alike(self, ci_env: Path) -> None:
        sarif = ci_env / "r.sarif"
        sarif.write_text(json.dumps(generate_sarif(_mixed())))
        first = _ci(str(sarif), "--sarif", str(ci_env / "again.sarif"))
        again = _ci(str(ci_env / "again.sarif"))
        assert first.exit_code == again.exit_code == 1

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
