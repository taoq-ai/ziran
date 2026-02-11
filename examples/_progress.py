"""Shared Rich progress bar for ZIRAN example scripts.

Provides a ``ZiranProgressBar`` context manager that hooks into the
scanner's ``on_progress`` callback to display a live progress bar
with per-attack and per-phase tracking.

Usage::

    from _progress import ZiranProgressBar

    async with ZiranProgressBar() as progress:
        result = await scanner.run_campaign(
            phases=my_phases,
            on_progress=progress.callback,
        )
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.console import Console

if TYPE_CHECKING:
    from types import TracebackType
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from ziran.application.agent_scanner.scanner import ProgressEvent, ProgressEventType


class ZiranProgressBar:
    """Rich-based progress bar driven by ZIRAN scanner progress events.

    Displays two nested bars:
    - **Campaign** — overall phase completion
    - **Phase** — per-attack completion within the current phase

    Example::

        async with ZiranProgressBar() as pb:
            result = await scanner.run_campaign(on_progress=pb.callback)
    """

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()
        self._progress: Progress | None = None
        self._campaign_task: Any = None
        self._phase_task: Any = None

    # -- async context-manager -------------------------------------------------

    async def __aenter__(self) -> ZiranProgressBar:
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self._console,
            expand=False,
        )
        self._progress.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._progress is not None:
            self._progress.stop()

    # -- callback --------------------------------------------------------------

    def callback(self, event: ProgressEvent) -> None:
        """Handle a ``ProgressEvent`` from the scanner.

        Designed to be passed directly as ``on_progress=pb.callback``.
        """
        assert self._progress is not None

        if event.event == ProgressEventType.CAMPAIGN_START:
            self._campaign_task = self._progress.add_task(
                "Campaign",
                total=event.total_phases,
            )

        elif event.event == ProgressEventType.PHASE_START:
            # Create a placeholder phase task (total set once attacks are loaded)
            if self._phase_task is not None:
                self._progress.remove_task(self._phase_task)
            label = _phase_label(event.phase or "unknown")
            self._phase_task = self._progress.add_task(
                label,
                total=None,  # indeterminate until PHASE_ATTACKS_LOADED
            )

        elif event.event == ProgressEventType.PHASE_ATTACKS_LOADED:
            # Now we know exactly how many attacks this phase has
            if self._phase_task is not None:
                self._progress.update(
                    self._phase_task,
                    total=max(event.total_attacks, 1),
                    completed=0,
                )

        elif event.event == ProgressEventType.ATTACK_COMPLETE:
            if self._phase_task is not None:
                self._progress.advance(self._phase_task)

        elif event.event == ProgressEventType.PHASE_COMPLETE:
            # Advance campaign bar
            if self._campaign_task is not None:
                self._progress.advance(self._campaign_task)
            # Finish phase bar
            if self._phase_task is not None:
                self._progress.remove_task(self._phase_task)
                self._phase_task = None

        elif event.event == ProgressEventType.CAMPAIGN_COMPLETE and self._campaign_task is not None:
            # Ensure bar shows 100%
            self._progress.update(
                self._campaign_task,
                completed=event.total_phases,
            )


def print_summary(result: Any, *, console: Console | None = None) -> None:
    """Print a compact Rich summary table after a campaign finishes.

    Args:
        result: A ``CampaignResult`` instance.
        console: Optional Rich console (creates one if not given).
    """
    con = console or Console()

    table = Table(
        title=f"[bold]ZIRAN Scan Results — {result.campaign_id}",
        show_lines=True,
    )
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")

    table.add_row("Target agent", result.target_agent)
    table.add_row("Phases run", str(len(result.phases_executed)))
    table.add_row("Total vulnerabilities", str(result.total_vulnerabilities))
    table.add_row("Critical attack paths", str(len(result.critical_paths)))
    table.add_row("Final trust score", f"{result.final_trust_score:.2f}")
    duration = result.metadata.get("duration_seconds", 0)
    table.add_row("Duration", f"{duration:.1f}s")

    con.print()
    con.print(table)


# -- helpers -------------------------------------------------------------------


def _phase_label(phase: str) -> str:
    """Human-friendly phase label."""
    return phase.replace("_", " ").title()
