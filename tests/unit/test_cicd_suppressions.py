"""Unit tests for the CI finding suppression baseline (spec 046, issue #395)."""

from __future__ import annotations

import json
import re
from datetime import date
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from ziran.application.cicd.gate import QualityGate, _composition_node_id, load_suppressions
from ziran.application.cicd.github_actions import emit_annotations, write_step_summary
from ziran.application.cicd.sarif import generate_sarif, write_sarif
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.domain.entities.capability import DangerousChain
from ziran.domain.entities.ci import (
    GateFinding,
    GateResult,
    GateStatus,
    QualityGateConfig,
    SuppressionEntry,
    SuppressionFile,
    attack_content_hash,
    attack_fingerprint,
    chain_content_hash,
    chain_fingerprint,
)
from ziran.domain.entities.phase import CampaignResult, PhaseResult, ScanPhase
from ziran.interfaces.cli.main import cli
from ziran.interfaces.web.services import findings_extractor

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

pytestmark = pytest.mark.unit

TODAY = date(2026, 1, 2)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMPOSITION = "composition::data_exfiltration::read_file->http_request"


# ── Helpers (pattern of tests/unit/test_cicd.py, copied locally) ─────


def _attack(
    vector_id: str = "v1",
    category: str = "prompt_injection",
    severity: str = "critical",
    **kw: Any,
) -> dict[str, Any]:
    ar: dict[str, Any] = {
        "vector_id": vector_id,
        "vector_name": f"Vector {vector_id}",
        "category": category,
        "severity": severity,
        "successful": True,
        "evidence": {"indicator": "compliance"},
        "agent_response": "I'll do that",
        "prompt_used": "ignore instructions",
        "owasp_mapping": ["LLM01"],
    }
    ar.update(kw)
    return ar


def _chain(
    tools: Sequence[str] = ("read_file", "http_request"),
    risk_level: str = "critical",
    vulnerability_type: str = "data_exfiltration",
) -> dict[str, Any]:
    return {
        "tools": list(tools),
        "risk_level": risk_level,
        "vulnerability_type": vulnerability_type,
    }


def _campaign(
    *,
    attacks: Sequence[dict[str, Any]] = (),
    chains: Sequence[dict[str, Any]] = (),
    critical_paths: Sequence[list[str]] = (),
    phase_vulns: Sequence[str] = (),
    success: bool = False,
) -> CampaignResult:
    phases = (
        [
            PhaseResult(
                phase=next(iter(ScanPhase)),
                success=True,
                trust_score=0.8,
                duration_seconds=0.0,
                vulnerabilities_found=list(phase_vulns),
            )
        ]
        if phase_vulns
        else []
    )
    return CampaignResult(
        campaign_id="test_campaign_001",
        target_agent="test_agent",
        phases_executed=phases,
        total_vulnerabilities=0,
        critical_paths=list(critical_paths),
        final_trust_score=0.8,
        success=success,
        attack_results=list(attacks),
        dangerous_tool_chains=list(chains),
    )


def _entry(finding: GateFinding, **kw: Any) -> SuppressionEntry:
    data: dict[str, Any] = {
        "fingerprint": finding.fingerprint,
        "content_hash": finding.content_hash,
        "reason": "accepted risk",
        "added_by": "sec-team",
    }
    data.update(kw)
    return SuppressionEntry(**data)


def _entries_for(result: CampaignResult, **kw: Any) -> SuppressionFile:
    return SuppressionFile(
        version=1, entries=[_entry(f, **kw) for f in QualityGate._findings(result)]
    )


def _states(gate: GateResult) -> list[str]:
    return [f.state for f in gate.findings]


def _rules(gate: GateResult) -> list[str]:
    return [v.rule for v in gate.violations]


def _eval(
    result: CampaignResult,
    sup: SuppressionFile | None,
    config: QualityGateConfig | None = None,
) -> GateResult:
    return QualityGate(config).evaluate(result, sup, today=TODAY)


# ── Domain: fingerprints and hashes ──────────────────────────────────


class TestFingerprints:
    def test_attack_fingerprint_pinned(self) -> None:
        assert (
            attack_fingerprint("test_agent", "v1", "prompt_injection")
            == "a8fe72c13edad12d1df1d032a83ebe7a5b0320e125cfc28de5321a0421117f6e"
        )
        assert findings_extractor._compute_fingerprint is attack_fingerprint

    def test_chain_fingerprint_identity(self) -> None:
        base = chain_fingerprint("test_agent", "data_exfiltration")
        assert chain_fingerprint("other_agent", "data_exfiltration") != base
        assert chain_fingerprint("test_agent", "sql_to_rce") != base
        findings = QualityGate._findings(
            _campaign(chains=[_chain(), _chain(tools=("read_file", "send_email"))])
        )
        assert findings[0].fingerprint == findings[1].fingerprint == base
        assert findings[0].content_hash != findings[1].content_hash

    def test_content_hashes(self) -> None:
        a = attack_content_hash("critical", "prompt_injection")
        assert attack_content_hash("high", "prompt_injection") != a
        assert attack_content_hash("critical", "data_exfiltration") != a
        c = chain_content_hash(["read_file", "http_request"], "critical")
        assert chain_content_hash(["http_request", "read_file"], "critical") != c
        assert chain_content_hash(["read_file", "send_email"], "critical") != c
        assert chain_content_hash(["read_file", "http_request"], "high") != c
        for h in (a, c, attack_fingerprint("a", "b", "c"), chain_fingerprint("a", "b")):
            assert HEX64.match(h)


# ── Domain: file models ──────────────────────────────────────────────


_FP = "a" * 64
_CH = "b" * 64


def _raw_entry(**kw: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "fingerprint": _FP,
        "content_hash": _CH,
        "reason": "ok",
        "added_by": "me",
    }
    data.update(kw)
    return data


class TestSuppressionModels:
    def test_valid_entries(self) -> None:
        assert SuppressionEntry(**_raw_entry()).expires is None
        assert SuppressionEntry(**_raw_entry(expires=date(2026, 12, 31))).expires == date(
            2026, 12, 31
        )
        assert SuppressionEntry(**_raw_entry(expires="2026-12-31")).expires == date(2026, 12, 31)
        assert SuppressionEntry(**_raw_entry(reason="  spaced  ")).reason == "spaced"
        assert SuppressionFile(version=1).entries == []

    @pytest.mark.parametrize(
        "bad",
        [
            {"extra": "x"},
            {"reason": ""},
            {"reason": "   "},
            {"added_by": ""},
            {"added_by": "  "},
            {"fingerprint": "a" * 63},
            {"fingerprint": "A" * 64},
            {"content_hash": "b" * 63},
            {"content_hash": "B" * 64},
            {"expires": "soon"},
        ],
    )
    def test_invalid_entry(self, bad: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            SuppressionEntry(**_raw_entry(**bad))

    @pytest.mark.parametrize("missing", ["reason", "added_by", "fingerprint", "content_hash"])
    def test_missing_entry_field(self, missing: str) -> None:
        data = _raw_entry()
        del data[missing]
        with pytest.raises(ValidationError):
            SuppressionEntry(**data)

    @pytest.mark.parametrize(
        "bad",
        [{"version": 2}, {}, {"version": 1, "extra": True}],
    )
    def test_invalid_file(self, bad: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            SuppressionFile.model_validate(bad)

    def test_expired(self) -> None:
        d = date(2026, 6, 1)
        assert not SuppressionEntry(**_raw_entry(expires=d)).expired(d)
        assert SuppressionEntry(**_raw_entry(expires=date(2026, 5, 31))).expired(d)
        assert not SuppressionEntry(**_raw_entry()).expired(d)

    def test_frozen(self) -> None:
        entry = SuppressionEntry(**_raw_entry())
        with pytest.raises(ValidationError):
            entry.reason = "x"
        sf = SuppressionFile(version=1)
        with pytest.raises(ValidationError):
            sf.entries = []

    def test_gate_result_defaults(self) -> None:
        g = GateResult(status=GateStatus.PASSED)
        assert g.findings == []
        assert (g.new_findings, g.suppressed_findings, g.regressed_findings) == (0, 0, 0)
        assert g.suppressions_applied is False
        assert g.suppressed_attacks() == {}


# ── Application: loading ─────────────────────────────────────────────


class TestLoadSuppressions:
    def test_valid(self, tmp_path: Path) -> None:
        p = tmp_path / "s.yaml"
        p.write_text(
            f"version: 1\nentries:\n  - fingerprint: {_FP}\n    content_hash: {_CH}\n"
            "    reason: accepted\n    added_by: sec\n    expires: 2026-12-31\n"
        )
        sf = load_suppressions(p)
        assert sf.entries[0].expires == date(2026, 12, 31)

    def test_list_document(self, tmp_path: Path) -> None:
        p = tmp_path / "s.yaml"
        p.write_text("- 1\n- 2\n")
        with pytest.raises(ValueError, match="expected mapping"):
            load_suppressions(p)

    def test_schema_error(self, tmp_path: Path) -> None:
        p = tmp_path / "s.yaml"
        p.write_text("version: 2\n")
        with pytest.raises(ValueError):
            load_suppressions(p)

    def test_missing(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_suppressions(tmp_path / "nope.yaml")


# ── Application: gate classification ─────────────────────────────────


class TestGateSuppressions:
    def test_suppressed_attack_does_not_fail(self) -> None:
        r = _campaign(attacks=[_attack()])
        g = _eval(r, _entries_for(r))
        assert g.passed
        assert g.finding_counts.critical == 0
        assert (g.new_findings, g.suppressed_findings, g.regressed_findings) == (0, 1, 0)
        assert g.suppressions_applied
        assert "Suppressions: new 0, suppressed 1, regressed 0" in g.summary
        assert g.suppressed_attacks() == {0: "accepted risk"}

    def test_suppressed_chain_does_not_fail(self) -> None:
        r = _campaign(chains=[_chain()])
        g = _eval(r, _entries_for(r))
        assert g.passed
        assert g.finding_counts.total == 0
        assert _states(g) == ["suppressed"]
        assert g.suppressed_attacks() == {}

    def test_all_suppressed_default_config_passes(self) -> None:
        r = _campaign(
            attacks=[_attack()],
            chains=[_chain()],
            critical_paths=[["cap_x", "v1"], ["read_file", COMPOSITION]],
            phase_vulns=["v1"],
            success=True,
        )
        g = _eval(r, _entries_for(r))
        assert g.passed, g.violations
        assert g.exit_code == 0

    def test_unbacked_data_source_path_fails(self) -> None:
        r = _campaign(
            attacks=[_attack()],
            chains=[_chain()],
            critical_paths=[
                ["cap_x", "v1"],
                ["read_file", COMPOSITION],
                ["cap_x", "sensitive_data"],
            ],
            phase_vulns=["v1"],
            success=True,
        )
        g = _eval(r, _entries_for(r))
        assert _rules(g) == ["policy_violation"]
        assert "1 unbacked critical path(s)" in g.violations[0].message
        assert g.violations[0].severity == "critical"

    def test_empty_path_is_unbacked(self) -> None:
        r = _campaign(attacks=[_attack()], critical_paths=[[]], success=True)
        g = _eval(r, _entries_for(r))
        assert "1 unbacked critical path(s)" in g.violations[0].message

    def test_unbacked_phase_vulnerability_fails(self) -> None:
        r = _campaign(
            attacks=[_attack()],
            chains=[_chain()],
            critical_paths=[["cap_x", "v1"]],
            phase_vulns=["v1", "v9"],
            success=True,
        )
        g = _eval(r, _entries_for(r))
        assert _rules(g) == ["policy_violation"]
        assert (
            g.violations[0].message
            == "Unsuppressed findings or unbacked critical paths were found (0 unsuppressed "
            "finding(s), 0 unbacked critical path(s), 1 unbacked phase vulnerability(ies))"
        )

    def test_policy_disabled_ignores_paths(self) -> None:
        r = _campaign(attacks=[_attack()], critical_paths=[["cap_x", "sensitive_data"]])
        g = _eval(r, _entries_for(r), QualityGateConfig(fail_on_policy_violation=False))
        assert g.passed

    def test_composition_node_id_matches_graph(self) -> None:
        graph_id = AttackKnowledgeGraph().add_chain_finding(
            DangerousChain(**_chain(), exploit_description="x")
        )
        assert _composition_node_id(_chain()) == graph_id == COMPOSITION

    def test_entry_valid_on_expiry_day(self) -> None:
        r = _campaign(attacks=[_attack()])
        g = _eval(r, _entries_for(r, expires=TODAY))
        assert g.passed
        assert _states(g) == ["suppressed"]

    def test_chain_tools_change_regresses(self) -> None:
        sup = _entries_for(_campaign(chains=[_chain()]))
        r = _campaign(chains=[_chain(tools=("read_file", "send_email"))])
        g = _eval(r, sup)
        assert _states(g) == ["regressed"]
        assert g.regressed_findings == 1
        assert g.finding_counts.critical == 1
        assert g.status == GateStatus.FAILED
        reg = [v for v in g.violations if v.rule == "suppression_regressed"]
        assert len(reg) == 1
        fp = sup.entries[0].fingerprint
        assert reg[0].message == (
            f"Suppressed finding {fp} changed: content hash is now "
            f"{g.findings[0].content_hash}; review it and update the entry"
        )
        assert reg[0].severity == "high"

    def test_attack_severity_change_regresses(self) -> None:
        sup = _entries_for(_campaign(attacks=[_attack(severity="high")]))
        g = _eval(_campaign(attacks=[_attack(severity="critical")]), sup)
        assert _states(g) == ["regressed"]
        assert "suppression_regressed" in _rules(g)

    def test_chain_risk_change_regresses(self) -> None:
        sup = _entries_for(_campaign(chains=[_chain(risk_level="high")]))
        g = _eval(_campaign(chains=[_chain(risk_level="critical")]), sup)
        assert _states(g) == ["regressed"]

    def test_evidence_and_text_changes_stay_suppressed(self) -> None:
        sup = _entries_for(_campaign(attacks=[_attack()]))
        changed = _attack(
            evidence={"tool_calls": [{"name": "http_request", "args": {"u": "x"}}]},
            agent_response="different",
            prompt_used="other prompt",
            vector_name="Renamed",
        )
        g = _eval(_campaign(attacks=[changed]), sup)
        assert _states(g) == ["suppressed"]
        assert g.passed

    def test_chain_extra_fields_stay_suppressed(self) -> None:
        sup = _entries_for(_campaign(chains=[_chain()]))
        changed = {**_chain(), "evidence": {"tool_calls": ["x"]}, "exploit_description": "new"}
        assert _states(_eval(_campaign(chains=[changed]), sup)) == ["suppressed"]

    def test_category_change_is_new(self) -> None:
        sup = _entries_for(_campaign(attacks=[_attack()]))
        g = _eval(_campaign(attacks=[_attack(category="data_exfiltration")]), sup)
        assert _states(g) == ["new"]
        assert "suppression_regressed" not in _rules(g)

    def test_duplicate_fingerprints(self) -> None:
        r = _campaign(chains=[_chain(), _chain(tools=("read_file", "send_email"))])
        assert _states(_eval(r, _entries_for(r))) == ["suppressed", "suppressed"]
        one = _entries_for(_campaign(chains=[_chain()]))
        assert _states(_eval(r, one)) == ["suppressed", "regressed"]

    def test_expired_entry_does_not_suppress(self) -> None:
        r = _campaign(attacks=[_attack()])
        sup = _entries_for(r, expires=date(2026, 1, 1))
        g = _eval(r, sup)
        assert _states(g) == ["new"]
        assert "severity_threshold_critical" in _rules(g)
        exp = [v for v in g.violations if v.rule == "suppression_expired"]
        fp = sup.entries[0].fingerprint
        assert exp[0].message == (
            f"Suppression {fp} expired on 2026-01-01 (reason: accepted risk); "
            "renew or remove the entry"
        )
        assert exp[0].severity == "high"

    def test_expired_unmatched_entry_fails(self) -> None:
        sup = _entries_for(_campaign(attacks=[_attack()]), expires=date(2025, 1, 1))
        g = _eval(_campaign(), sup)
        assert _rules(g) == ["suppression_expired"]
        assert g.status == GateStatus.FAILED

    def test_expired_and_active_entries(self) -> None:
        r = _campaign(attacks=[_attack()])
        f = QualityGate._findings(r)[0]
        sup = SuppressionFile(
            version=1,
            entries=[
                _entry(f, content_hash="c" * 64),
                _entry(f, expires=date(2025, 1, 1)),
            ],
        )
        g = _eval(r, sup)
        assert _states(g) == ["regressed"]
        assert "suppression_regressed" in _rules(g)
        assert "suppression_expired" in _rules(g)

    def test_stale_entry_ignored(self) -> None:
        sup = _entries_for(_campaign(attacks=[_attack(vector_id="gone")]))
        g = _eval(_campaign(), sup)
        assert g.passed
        assert g.violations == []

    def test_new_finding_fails(self) -> None:
        sup = _entries_for(_campaign(attacks=[_attack()]))
        g = _eval(_campaign(attacks=[_attack(), _attack(vector_id="v2")]), sup)
        assert (g.new_findings, g.suppressed_findings, g.regressed_findings) == (1, 1, 0)
        assert g.finding_counts.critical == 1
        assert "max_critical_findings" in _rules(g)
        assert "severity_threshold_critical" in _rules(g)

    def test_unsuccessful_attacks_not_classified(self) -> None:
        g = _eval(_campaign(attacks=[_attack(successful=False)]), SuppressionFile(version=1))
        assert g.findings == []
        assert g.passed

    def test_info_severity_counted_in_states_only(self) -> None:
        g = _eval(_campaign(attacks=[_attack(severity="info")]), SuppressionFile(version=1))
        assert _states(g) == ["new"]
        assert g.new_findings == 1
        assert g.finding_counts.total == 0
        assert _rules(g) == ["policy_violation"]

    def test_violation_order(self) -> None:
        sup_r = _entries_for(_campaign(chains=[_chain(risk_level="high")]))
        expired = _entries_for(
            _campaign(attacks=[_attack(vector_id="old")]), expires=date(2025, 1, 1)
        )
        sup = SuppressionFile(version=1, entries=[*sup_r.entries, *expired.entries])
        g = _eval(_campaign(attacks=[_attack()], chains=[_chain()]), sup)
        assert _rules(g) == [
            "max_critical_findings",
            "severity_threshold_critical",
            "policy_violation",
            "suppression_regressed",
            "suppression_expired",
        ]


# ── Absent file: unchanged behaviour ─────────────────────────────────


class TestAbsent:
    @pytest.mark.parametrize(
        ("result", "status", "rules", "counts"),
        [
            (_campaign(), GateStatus.PASSED, [], (0, 0, 0, 0)),
            (
                _campaign(
                    attacks=[_attack(), _attack(vector_id="v2", severity="medium")], success=True
                ),
                GateStatus.FAILED,
                ["max_critical_findings", "severity_threshold_critical", "policy_violation"],
                (1, 0, 1, 0),
            ),
            (
                _campaign(chains=[_chain()], success=True),
                GateStatus.FAILED,
                ["max_critical_findings", "severity_threshold_critical", "policy_violation"],
                (1, 0, 0, 0),
            ),
            (_campaign(success=True), GateStatus.FAILED, ["policy_violation"], (0, 0, 0, 0)),
            (_campaign(chains=[_chain(risk_level="high")]), GateStatus.PASSED, [], (0, 1, 0, 0)),
        ],
    )
    def test_unchanged(
        self,
        result: CampaignResult,
        status: GateStatus,
        rules: list[str],
        counts: tuple[int, int, int, int],
    ) -> None:
        for g in (QualityGate().evaluate(result), QualityGate().evaluate(result, None)):
            assert g.status == status
            assert _rules(g) == rules
            fc = g.finding_counts
            assert (fc.critical, fc.high, fc.medium, fc.low) == counts
            assert "Suppressions:" not in g.summary
            assert g.suppressions_applied is False
            assert set(_states(g)) <= {"new"}
            assert (g.suppressed_findings, g.regressed_findings) == (0, 0)
            if "policy_violation" in rules:
                assert g.violations[-1].message == (
                    "Critical attack paths or tool-composition chains were found"
                )
        assert QualityGate._count_findings(result) == QualityGate._tally(
            QualityGate._findings(result)
        )


# ── SARIF and GitHub Actions ─────────────────────────────────────────


def _mixed() -> tuple[CampaignResult, GateResult]:
    """`v1` suppressed, `v2` new."""
    sup = _entries_for(_campaign(attacks=[_attack()]))
    r = _campaign(attacks=[_attack(), _attack(vector_id="v2")])
    return r, _eval(r, sup)


class TestSarifSuppressions:
    def test_suppressed_result_marked(self) -> None:
        r, g = _mixed()
        doc = generate_sarif(r, g)
        results = doc["runs"][0]["results"]
        assert results[0]["suppressions"] == [
            {"kind": "external", "justification": "accepted risk"}
        ]
        assert "suppressions" not in results[1]
        assert (
            doc["runs"][0]["tool"]["driver"]["rules"]
            == generate_sarif(r)["runs"][0]["tool"]["driver"]["rules"]
        )

    def test_no_file_unchanged(self) -> None:
        r = _campaign(attacks=[_attack(), _attack(vector_id="v2")])
        plain = generate_sarif(r)
        assert generate_sarif(r, QualityGate().evaluate(r)) == plain
        assert "suppressions" not in json.dumps(plain)

    def test_write(self, tmp_path: Path) -> None:
        r, g = _mixed()
        p = write_sarif(r, tmp_path / "r.sarif", g)
        assert "suppressions" in json.loads(p.read_text())["runs"][0]["results"][0]


class TestGitHubActionsSuppressions:
    def test_annotations_skip_suppressed(self) -> None:
        r, g = _mixed()
        anns = emit_annotations(r, g)
        assert len(anns) == 1
        assert "Vector: v2" in anns[0]
        assert len(emit_annotations(r)) == 2

    def test_step_summary(self) -> None:
        r, g = _mixed()
        md = write_step_summary(g, r, summary_path=None)
        assert "Vector v1" not in md
        assert "Vector v2" in md
        assert "### Suppressions" in md
        assert "| New | 1 |" in md
        assert "| Suppressed | 1 |" in md
        assert "| Regressed | 0 |" in md
        assert "| Critical | 1 |" in md

    def test_step_summary_no_file(self) -> None:
        r = _campaign(attacks=[_attack()])
        md = write_step_summary(QualityGate().evaluate(r), r, summary_path=None)
        assert "### Suppressions" not in md
        assert "Vector v1" in md


# ── CLI ──────────────────────────────────────────────────────────────


@pytest.fixture()
def ci_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    return tmp_path


def _write_result(path: Path, result: CampaignResult) -> str:
    path.write_text(result.model_dump_json())
    return str(path)


def _write_sup(path: Path, sup: SuppressionFile) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sup.model_dump(mode="json")))  # JSON is valid YAML
    return path


def _ci(*args: str) -> Any:
    return CliRunner().invoke(cli, ["ci", *args], terminal_width=80)


class TestCiCommandSuppressions:
    def test_auto_load(self, ci_env: Path) -> None:
        r = _campaign(attacks=[_attack()])
        _write_sup(ci_env / ".ziran" / "suppressions.yaml", _entries_for(r))
        out = _ci(_write_result(ci_env / "r.json", r))
        assert out.exit_code == 0, out.output
        assert "Suppressed: 1" in out.output

    def test_flag_overrides_cwd_file(self, ci_env: Path) -> None:
        r = _campaign(attacks=[_attack()])
        (ci_env / ".ziran").mkdir()
        (ci_env / ".ziran" / "suppressions.yaml").write_text("not: [valid")
        other = _write_sup(ci_env / "other.yaml", _entries_for(r))
        out = _ci(_write_result(ci_env / "r.json", r), "--suppressions", str(other))
        assert out.exit_code == 0, out.output

    def test_flag_missing_path(self, ci_env: Path) -> None:
        r = _write_result(ci_env / "r.json", _campaign())
        assert _ci(r, "--suppressions", "missing.yaml").exit_code == 2

    def test_malformed_auto_loaded(self, ci_env: Path) -> None:
        (ci_env / ".ziran").mkdir()
        (ci_env / ".ziran" / "suppressions.yaml").write_text("version: 2\n")
        out = _ci(_write_result(ci_env / "r.json", _campaign()))
        assert out.exit_code == 1
        assert "Error loading suppressions" in out.output

    def test_malformed_flag(self, ci_env: Path) -> None:
        bad = ci_env / "bad.yaml"
        bad.write_text("- a\n")
        out = _ci(_write_result(ci_env / "r.json", _campaign()), "--suppressions", str(bad))
        assert out.exit_code == 1
        assert "Error loading suppressions" in out.output

    def test_ci_prints_fingerprints(self, ci_env: Path) -> None:
        (ci_env / ".ziran").mkdir()
        (ci_env / ".ziran" / "suppressions.yaml").write_text("version: 1\n")
        r = _campaign(attacks=[_attack()])
        f = QualityGate._findings(r)[0]
        out = _ci(_write_result(ci_env / "r.json", r))
        assert out.exit_code == 1
        assert (
            f"  new attack v1 [critical] fingerprint={f.fingerprint} content_hash={f.content_hash}"
            in out.output.splitlines()
        )

    def test_github_outputs(self, ci_env: Path) -> None:
        r = _campaign(attacks=[_attack()])
        _write_sup(ci_env / ".ziran" / "suppressions.yaml", _entries_for(r))
        _ci(_write_result(ci_env / "r.json", r))
        lines = (ci_env / "out.txt").read_text().splitlines()
        assert [ln.split("=")[0] for ln in lines] == [
            "status",
            "trust_score",
            "total_findings",
            "critical_findings",
            "new_findings",
            "suppressed_findings",
            "regressed_findings",
        ]
        assert lines[4:] == ["new_findings=0", "suppressed_findings=1", "regressed_findings=0"]

    def test_sarif_via_cli(self, ci_env: Path) -> None:
        r = _campaign(attacks=[_attack()])
        _write_sup(ci_env / ".ziran" / "suppressions.yaml", _entries_for(r))
        _ci(_write_result(ci_env / "r.json", r), "--sarif", "r.sarif")
        doc = json.loads((ci_env / "r.sarif").read_text())
        assert doc["runs"][0]["results"][0]["suppressions"][0]["kind"] == "external"

    def test_absent(self, ci_env: Path) -> None:
        r = _campaign(attacks=[_attack()])
        out = _ci(_write_result(ci_env / "r.json", r), "--sarif", "r.sarif")
        assert out.exit_code == 1
        assert "fingerprint=" not in out.output
        assert "Suppressed:" not in out.output
        assert len((ci_env / "out.txt").read_text().splitlines()) == 4
        assert "suppressions" not in (ci_env / "r.sarif").read_text()
        assert "### Suppressions" not in (ci_env / "summary.md").read_text()
