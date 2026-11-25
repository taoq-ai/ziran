"""Target text the CLI prints to a terminal is inert: no raw control sequence, no live markup."""

from __future__ import annotations

import io
import re
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from ziran.domain.entities.ci import FindingCount, GateFinding, GateResult, GateStatus
from ziran.domain.entities.pentest import (
    DeduplicatedFinding,
    PentestSession,
    PentestStep,
    PentestStepType,
)
from ziran.domain.entities.phase import CampaignResult
from ziran.domain.entities.registry import DriftFinding
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
_SGR = re.compile(re.escape(ESC) + r"\[[0-9;]*m")  # Rich's own colour codes


@pytest.fixture
def screen(monkeypatch: pytest.MonkeyPatch) -> Iterator[io.StringIO]:
    buf = io.StringIO()
    term = Console(file=buf, force_terminal=True, width=400, color_system="truecolor")
    for module in (main, analyze_traces, watch_registry):
        monkeypatch.setattr(module, "console", term)
    yield buf


def _campaign() -> CampaignResult:
    return CampaignResult(
        campaign_id="c",
        target_agent=HOSTILE,
        phases_executed=[],
        total_vulnerabilities=0,
        final_trust_score=1.0,
        success=True,
        critical_paths=[["read", HOSTILE]],
        dangerous_tool_chains=[
            {
                "tools": ["read", HOSTILE],
                "risk_level": "high",
                "vulnerability_type": HOSTILE,
                "exploit_description": HOSTILE,
            }
        ],
        warnings=[HOSTILE],
    )


def _scan() -> None:
    main._display_results(_campaign())


def _traces() -> None:
    analyze_traces._display_summary(_campaign())


def _audit() -> None:
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


def _gate() -> None:
    main._display_gate_result(
        GateResult(
            status=GateStatus.FAILED,
            trust_score=0.1,
            finding_counts=FindingCount(high=1),
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
            summary="s",
        )
    )


def _pentest() -> None:
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
            severity="high",
            owasp_categories=["LLM01"],
            attack_result_ids=["v1"],
        )
    ]
    main._display_session_results(session)


def _registry() -> None:
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


@pytest.mark.unit
@pytest.mark.parametrize(
    "render", [_scan, _traces, _audit, _gate, _pentest, _registry], ids=lambda f: f.__name__
)
def test_hostile_target_text_prints_inert(screen: io.StringIO, render: Callable[[], Any]) -> None:
    render()
    out = screen.getvalue()
    assert ESC not in _SGR.sub("", out)  # no OSC 52, OSC 8 or CSI 2J reached the terminal
    assert RLO not in out
    assert "[link=http://evil.example]" in out  # the markup shows as text, not a hyperlink
    assert "\\x1b]52" in out  # the escape is visible to the reader
