"""Target text the CLI prints to a terminal is inert: no raw control sequence, no live markup."""

from __future__ import annotations

import contextlib
import io
import logging
import re
import urllib.error
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner
from rich.console import Console
from rich.prompt import Prompt

from ziran.application.agent_scanner.scanner import ProgressEvent, ProgressEventType
from ziran.application.pentesting.progress import PentestProgressDisplay
from ziran.application.static_analysis import claude_code_audit, claude_code_baseline
from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.entities.ci import (
    FindingCount,
    GateFinding,
    GateResult,
    GateStatus,
    GateViolation,
)
from ziran.domain.entities.pentest import (
    DeduplicatedFinding,
    PentestSession,
    PentestStep,
    PentestStepType,
)
from ziran.domain.entities.phase import CampaignResult, PhaseResult, ScanPhase
from ziran.domain.entities.policy import PolicyVerdict, PolicyViolation, RuleType
from ziran.domain.entities.registry import DriftFinding
from ziran.infrastructure.config import claude_code_plugin
from ziran.infrastructure.logging.logger import _build_handler
from ziran.interfaces.cli import analyze_traces, main, watch_registry

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

ESC = chr(0x1B)
BEL = chr(0x07)
RLO = chr(0x202E)
# OSC 52 clipboard write, OSC 8 hyperlink, CSI 2J screen clear, Rich link markup, bidi override.
HOSTILE = (
    "[link=http://evil.example]click[/link][bold]x[/bold]"
    f"{ESC}]52;c;Y2xp{BEL}{ESC}]8;;http://evil.example{ESC}\\go{ESC}]8;;{ESC}\\"
    f"{ESC}[2J{RLO}tool"
)
# Rich's own codes: colours, and the cursor moves of a status spinner.
_OWN = re.compile(re.escape(ESC) + r"\[(?:[0-9;]*m|\?25[lh]|1A|2K)")


LINK = "[link=http://evil.example]click[/link]"


def _terminal(buf: io.StringIO) -> Console:
    return Console(file=buf, force_terminal=True, width=400, color_system="truecolor")


@pytest.fixture
def screen(monkeypatch: pytest.MonkeyPatch) -> Iterator[io.StringIO]:
    buf = io.StringIO()
    term = _terminal(buf)
    for module in (main, analyze_traces, watch_registry):
        monkeypatch.setattr(module, "console", term)
    for key in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
        monkeypatch.delenv(key, raising=False)
    yield buf


def _assert_inert(out: str) -> None:
    text = _OWN.sub("", out)
    assert ESC not in text  # no OSC 52, OSC 8 or CSI 2J reached the terminal
    assert RLO not in text
    assert LINK in text  # the markup shows as text, not a hyperlink
    assert "\\x1b]52" in text  # the escape is visible to the reader


def _campaign() -> CampaignResult:
    vuln = {"name": HOSTILE, "severity": HOSTILE}
    return CampaignResult(
        campaign_id=HOSTILE,
        target_agent=HOSTILE,
        phases_executed=[
            PhaseResult(
                phase=ScanPhase.RECONNAISSANCE,
                success=True,
                artifacts={"v1": vuln},
                trust_score=0.5,
                vulnerabilities_found=["v1"],
                duration_seconds=1.0,
            )
        ],
        total_vulnerabilities=1,
        final_trust_score=0.5,
        success=True,
        critical_paths=[["read", HOSTILE]],
        dangerous_tool_chains=[
            {
                "tools": ["read", HOSTILE],
                "risk_level": HOSTILE,
                "vulnerability_type": HOSTILE,
                "exploit_description": HOSTILE,
            }
        ],
        metadata={"warnings": [HOSTILE]},
    )


def _session() -> PentestSession:
    session = PentestSession(max_iterations=1)
    session.add_step(
        PentestStep(
            step_type=PentestStepType.SCAN,
            reasoning="r",
            tool_name=HOSTILE,
            result_summary=HOSTILE,
            duration_seconds=1.0,
        )
    )
    session.findings = [
        DeduplicatedFinding(
            canonical_title=HOSTILE,
            canonical_description="d",
            severity=HOSTILE,
            owasp_categories=["LLM01"],
            attack_result_ids=["v1"],
        )
    ]
    return session


def _scan(tmp_path: Any) -> None:
    main._display_results(_campaign())


def _traces(tmp_path: Any) -> None:
    analyze_traces._display_summary(_campaign())


def _audit(tmp_path: Any) -> None:
    finding = MagicMock(
        check_id="SA001",
        severity="high",
        message=HOSTILE,
        file_path=HOSTILE,
        line_number=1,
        recommendation=HOSTILE,
    )
    report = MagicMock(
        findings=[finding],
        total_issues=1,
        files_analyzed=1,
        critical_count=0,
        high_count=1,
        passed=True,
    )
    main._display_audit_report(report)


def _gate(tmp_path: Any) -> None:
    main._display_gate_result(
        GateResult(
            status=GateStatus.FAILED,
            trust_score=0.1,
            finding_counts=FindingCount(high=1),
            violations=[GateViolation(rule="r", message=HOSTILE, severity="high")],
            findings=[
                GateFinding(
                    kind="chain",
                    index=0,
                    label=HOSTILE,
                    severity="high",
                    fingerprint="f",
                    content_hash="h",
                )
            ],
            suppressions_applied=True,
            summary=HOSTILE,
        )
    )


def _ci_warnings(tmp_path: Any) -> None:
    result = tmp_path / "result.json"
    result.write_text(_campaign().model_dump_json())
    args = ["ci", str(result), "--no-github-annotations", "--no-github-summary"]
    CliRunner().invoke(main.cli, args)


def _policy(tmp_path: Any) -> None:
    hostile = [PolicyViolation(rule_type=RuleType.MAX_CRITICAL_VULNS, message=HOSTILE)]
    verdict = PolicyVerdict(
        policy_id="p",
        policy_name="p",
        passed=True,
        violations=hostile,
        warnings=hostile,
        info=hostile,
        summary=HOSTILE,
    )
    main._display_policy_verdict(verdict)


def _audit_narrowed(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    narrowed = [claude_code_baseline.BaselineNarrowing(agent=HOSTILE, change="tool_removed")]
    monkeypatch.setattr(claude_code_plugin, "load_claude_code", lambda _p: MagicMock(detected=True))
    monkeypatch.setattr(
        claude_code_audit,
        "audit_claude_code",
        lambda *_a, **_k: MagicMock(files_analyzed=0, findings=[]),
    )
    monkeypatch.setattr(claude_code_baseline, "apply_baseline", lambda *_a: ([], narrowed))
    monkeypatch.setattr(main, "_trifecta_roles", dict)
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"version": 1, "agents": {}}')
    CliRunner().invoke(main.cli, ["audit", str(tmp_path), "--baseline", str(baseline)])


def _discover(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    cap = AgentCapability(id=HOSTILE, name=HOSTILE, type=CapabilityType.TOOL, description=HOSTILE)
    adapter = MagicMock(discover_capabilities=AsyncMock(return_value=[cap]))
    monkeypatch.setattr(main, "load_remote_adapter", lambda *_a: (adapter, None))
    target = tmp_path / "target.yaml"
    target.write_text("url: http://localhost\n")
    CliRunner().invoke(main.cli, ["discover", "--target", str(target)])


def _validate(tmp_path: Any) -> None:
    error = urllib.error.HTTPError("http://localhost", 404, HOSTILE, None, None)  # type: ignore[arg-type]
    with contextlib.suppress(SystemExit):  # a failed check exits 1
        main._display_validation_results([("URL reachable", False, str(error))])


def _pentest(tmp_path: Any) -> None:
    main._display_session_results(_session())


def _pentest_repl(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session()
    replies = iter(["/findings", "go", "/quit"])
    monkeypatch.setattr(Prompt, "ask", lambda *_a, **_k: next(replies))
    orchestrator = MagicMock(
        start_interactive=AsyncMock(return_value=session),
        send_directive=AsyncMock(return_value=session),
        export_report=AsyncMock(return_value=[]),
    )
    main._run_interactive_mode(orchestrator, "goal", str(tmp_path))


def _registry(tmp_path: Any) -> None:
    watch_registry._print_summary(
        [
            DriftFinding(
                server_name=HOSTILE,
                drift_type="tool_added",
                severity="high",
                tool_name=HOSTILE,
                message=HOSTILE,
            )
        ]
    )


def _progress(tmp_path: Any) -> None:
    display = PentestProgressDisplay(console=main.console)
    display.on_agent_event("execute", HOSTILE)
    display.on_progress(
        ProgressEvent(
            event=ProgressEventType.ATTACK_COMPLETE,
            attack_name=HOSTILE,
            extra={"successful": True},
        )
    )


_RENDERERS: list[Callable[..., Any]] = [
    _scan,
    _traces,
    _audit,
    _audit_narrowed,
    _gate,
    _ci_warnings,
    _policy,
    _discover,
    _validate,
    _pentest,
    _pentest_repl,
    _registry,
    _progress,
]


@pytest.mark.unit
@pytest.mark.parametrize("render", _RENDERERS, ids=lambda f: f.__name__.lstrip("_"))
def test_hostile_target_text_prints_inert(
    screen: io.StringIO,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    render: Callable[..., Any],
) -> None:
    if "monkeypatch" in render.__code__.co_varnames[: render.__code__.co_argcount]:
        render(tmp_path, monkeypatch)
    else:
        render(tmp_path)
    _assert_inert(screen.getvalue())


@pytest.mark.unit
def test_log_lines_show_target_markup_as_text() -> None:
    buf = io.StringIO()
    handler = _build_handler("text", "INFO", rich_tracebacks=False)
    handler.console = _terminal(buf)  # type: ignore[attr-defined]
    record = logging.LogRecord(
        "ziran", logging.INFO, __file__, 1, f"agent_card_loaded {LINK}", None, None
    )
    handler.emit(record)
    out = buf.getvalue()
    assert "evil.example" not in "".join(re.findall(re.escape(ESC) + r"\]8;[^;]*;([^\x1b]*)", out))
    assert LINK in _OWN.sub("", out)
