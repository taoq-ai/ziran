"""Goal state in every report format and the ci gate (spec 126)."""

from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner
from rich.console import Console

from ziran.application.agent_scanner.trials import combine
from ziran.application.cicd.gate import QualityGate
from ziran.application.goals import judge_goal
from ziran.domain.entities.attack import AttackPrompt, AttackResult, AttackVector
from ziran.domain.entities.ci import QualityGateConfig
from ziran.domain.entities.goal import GoalCall, LimitBreachGoal, goal_rows
from ziran.domain.entities.phase import CampaignResult, PhaseResult, ScanPhase
from ziran.interfaces.cli import main
from ziran.interfaces.cli.html_report import build_html_report
from ziran.interfaces.cli.reports import ReportGenerator

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit

HOSTILE = "<script>alert(1)</script>|[bold]x[/bold]"
COMMIT = GoalCall(turn=3, call=1, tool="submit_offer", role="commitment", argument="$.price")


def _row(
    vector_id: str, met: bool | None, evidence: list[GoalCall], **extra: Any
) -> dict[str, Any]:
    result = AttackResult(
        vector_id=vector_id,
        vector_name=vector_id,
        category="prompt_injection",
        severity="high",
        successful=False,
        goal_type="limit_breach",
        goal_met=met,
        goal_evidence=evidence,
        **extra,
    )
    return result.model_dump(mode="json")


def _campaign(*rows: dict[str, Any]) -> CampaignResult:
    phase = PhaseResult(
        phase=ScanPhase.RECONNAISSANCE, success=True, trust_score=1.0, duration_seconds=1.0
    )
    return CampaignResult(
        campaign_id="c",
        target_agent="t",
        phases_executed=[phase],
        total_vulnerabilities=0,
        final_trust_score=1.0,
        success=False,
        attack_results=list(rows),
    )


MET = _row("floor_breach", True, [COMMIT])
KEPT = _row("floor_kept", False, [])
UNREAD = _row("floor_unread", None, [])
PLAIN = {**_row("plain", None, []), "goal_type": None}


class TestGoalRows:
    def test_states_and_evidence(self) -> None:
        rows = goal_rows([MET, KEPT, UNREAD, PLAIN])
        assert [(r.vector_id, r.state) for r in rows] == [
            ("floor_breach", "met"),
            ("floor_kept", "not met"),
            ("floor_unread", "unmeasured"),
        ]
        assert rows[0].evidence == "turn 3: submit_offer commitment at $.price"
        assert rows[2].evidence == "no reply recorded"

    def test_an_older_file_without_goal_type_still_shows_a_verdict(self) -> None:
        old = {k: v for k, v in MET.items() if k != "goal_type"}
        assert [r.state for r in goal_rows([old])] == ["met"]

    def test_a_reply_entry_names_its_turn(self) -> None:
        reply = _row("secret", True, [GoalCall(turn=2, role="reply")])
        assert goal_rows([reply])[0].evidence == "turn 2: reply"


class TestReports:
    def test_markdown_shows_each_goal_state_with_its_turn(self) -> None:
        md = ReportGenerator._format_markdown(
            ReportGenerator.__new__(ReportGenerator), _campaign(MET, KEPT, UNREAD, PLAIN)
        )
        assert "| Goals Met | 1 of 3 (1 unmeasured) |" in md
        assert "| `floor_breach` | met | `turn 3: submit_offer commitment at $.price` |" in md
        assert "| `floor_unread` | unmeasured | `no reply recorded` |" in md
        assert "`plain`" not in md

    def test_markdown_keeps_hostile_target_text_inert(self) -> None:
        tool = "`x` | <img src=x onerror=alert(1)>\n# forged"
        hostile = _row("h", True, [COMMIT.model_copy(update={"tool": tool})])
        md = ReportGenerator._format_markdown(
            ReportGenerator.__new__(ReportGenerator), _campaign(hostile)
        )
        [row] = [line for line in md.splitlines() if line.startswith("| `h` |")]
        assert row.endswith(" |") and "\\|" in row  # one table row, the pipe escaped
        assert "\n# forged" not in md and "\\n# forged" in row  # the newline is shown, inert
        assert "``" in row  # the backticks sit inside a longer code fence

    def test_markdown_without_goal_vectors_is_unchanged(self) -> None:
        md = ReportGenerator._format_markdown(
            ReportGenerator.__new__(ReportGenerator), _campaign(PLAIN)
        )
        assert "Goal" not in md

    def test_html_shows_goal_states_and_escapes_the_target(self) -> None:
        hostile = _row("v", True, [COMMIT.model_copy(update={"tool": HOSTILE})])
        page = build_html_report(_campaign(MET, UNREAD, hostile).model_dump(mode="json"), {})
        assert "floor_breach" in page and "turn 3: submit_offer commitment at $.price" in page
        assert ">unmeasured<" in page
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page

    def test_html_without_goal_vectors_has_no_goal_section(self) -> None:
        page = build_html_report(_campaign(PLAIN).model_dump(mode="json"), {})
        assert "Side-effect goals" not in page

    def test_console_shows_goal_states(self, monkeypatch: pytest.MonkeyPatch) -> None:
        buf = io.StringIO()
        monkeypatch.setattr(main, "console", Console(file=buf, width=300))
        hostile = _row("h", True, [COMMIT.model_copy(update={"tool": HOSTILE})])
        main._display_results(_campaign(MET, UNREAD, hostile))
        out = buf.getvalue()
        assert "Goals Met" in out and "2 of 3 (1 unmeasured)" in out
        assert "floor_breach" in out and "turn 3: submit_offer commitment at $.price" in out
        assert "unmeasured" in out
        assert "[bold]x[/bold]" in out  # target text is shown, not read as markup


class TestGate:
    def test_a_met_goal_fails_only_when_the_gate_asks(self) -> None:
        campaign = _campaign(MET, KEPT, UNREAD)
        assert QualityGate().evaluate(campaign).passed
        gated = QualityGate(QualityGateConfig(fail_on_goal_met=True)).evaluate(campaign)
        assert not gated.passed
        [violation] = gated.violations
        assert (violation.rule, violation.severity) == ("goal_met", "critical")
        assert "floor_breach" in violation.message and "turn 3" in violation.message
        assert "floor_unread" not in violation.message

    def test_ci_exits_non_zero_naming_the_goal(self, tmp_path: Path) -> None:
        result = tmp_path / "result.json"
        clear = "\x1b[2J"  # a terminal control in a target's tool name
        hostile = _row("h", None, [COMMIT.model_copy(update={"tool": clear})])
        result.write_text(_campaign(MET, UNREAD, hostile).model_dump_json())
        gate = tmp_path / "gate.yaml"
        gate.write_text("fail_on_goal_met: true\n")
        args = ["ci", str(result), "--no-github-annotations", "--no-github-summary"]
        today = CliRunner().invoke(main.cli, args)
        assert today.exit_code == 0
        assert "floor_unread" in today.output  # an unmeasured goal is named, never silent
        assert "\x1b" not in today.output
        gated = CliRunner().invoke(main.cli, [*args, "--gate-config", str(gate)])
        assert gated.exit_code == 1
        assert "floor_breach" in gated.output

    def test_a_goal_gate_on_a_sarif_is_refused(self, tmp_path: Path) -> None:
        from ziran.application.cicd.sarif import write_sarif

        sarif = write_sarif(_campaign(MET), tmp_path / "r.sarif")
        gate = tmp_path / "gate.yaml"
        gate.write_text("fail_on_goal_met: true\n")
        args = ["ci", str(sarif), "-g", str(gate), "--no-github-annotations", "--no-github-summary"]
        run = CliRunner().invoke(main.cli, args)
        assert run.exit_code == 1
        assert "fail_on_goal_met needs the scan result JSON" in run.output
        assert CliRunner().invoke(main.cli, args[:2] + args[4:]).exit_code == 0

    def test_ci_stdout_never_starts_a_workflow_command(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(main, "console", Console(width=80))  # a CI runner's non-tty width
        # one padding per row, so some wrap point lands right before the command
        keys = ["$." + "a " * n + "::error title=forged::ZIRAN gate passed" for n in range(40)]
        forged = [COMMIT.model_copy(update={"argument": k}) for k in keys]
        rows = [_row(f"g{i}", i % 2 == 0 or None, [c]) for i, c in enumerate(forged)]
        campaign = _campaign(*rows)
        campaign.metadata["warnings"] = ["w " * n + "::stop-commands::x" for n in range(40)]
        result = tmp_path / "result.json"
        result.write_text(campaign.model_dump_json())
        gate = tmp_path / "gate.yaml"
        gate.write_text("fail_on_goal_met: true\n")
        args = ["ci", str(result), "-g", str(gate), "--no-github-annotations"]
        args.append("--no-github-summary")
        out = CliRunner().invoke(main.cli, args).output
        assert "::error title=forged::" in out
        assert not [line for line in out.splitlines() if line.lstrip().startswith("::")]

    def test_step_summary_keeps_a_goal_violation_inert(self, tmp_path: Path) -> None:
        from ziran.application.cicd.github_actions import write_step_summary

        tool = "a|b\n## forged `x` <b>"
        campaign = _campaign(_row("h", True, [COMMIT.model_copy(update={"tool": tool})]))
        gate = QualityGate(QualityGateConfig(fail_on_goal_met=True)).evaluate(campaign)
        summary = write_step_summary(gate, campaign, summary_path=str(tmp_path / "summary.md"))
        [row] = [line for line in summary.splitlines() if line.startswith("| goal_met |")]
        assert "\n## forged" not in summary and "<b>" not in summary and "a\\|b" in row

    def test_a_malformed_evidence_entry_is_skipped(self) -> None:
        row = {**MET, "goal_evidence": ["turn 3", COMMIT.model_dump(mode="json")]}
        assert goal_rows([row])[0].evidence == "turn 3: submit_offer commitment at $.price"


class TestRecording:
    def test_judge_records_the_goal_type(self) -> None:
        goal = LimitBreachGoal(
            type="limit_breach", tools=["submit_offer"], argument="price", floor=800
        )
        vector = AttackVector(
            id="v",
            name="v",
            category="prompt_injection",
            target_phase=ScanPhase.RECONNAISSANCE,
            description="d",
            severity="high",
            prompts=[AttackPrompt(template="hi")],
            goal=goal,
        )
        result = AttackResult(
            vector_id="v",
            vector_name="v",
            category="prompt_injection",
            severity="high",
            successful=False,
        )
        judged = judge_goal(vector, result, {})
        assert (judged.goal_type, judged.goal_met) == ("limit_breach", None)

    def test_a_goal_met_on_a_later_trial_shows_beside_a_text_success(self) -> None:
        first = AttackResult.model_validate({**KEPT, "successful": True})
        second = AttackResult.model_validate(MET)
        combined = combine([first, second], 2)
        assert combined.successful is True
        assert (combined.goal_met, combined.goal_evidence) == (True, [COMMIT])
        assert json.loads(combined.model_dump_json())["goal_type"] == "limit_breach"
