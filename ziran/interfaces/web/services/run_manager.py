"""RunManager — orchestrates scan execution and WebSocket progress broadcasting."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary
from ziran.application.factories import build_strategy, load_remote_adapter
from ziran.domain.entities.phase import CoverageLevel, ScanPhase
from ziran.interfaces.web.schemas import ProgressMessage

if TYPE_CHECKING:
    from fastapi import WebSocket
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

logger = logging.getLogger(__name__)


class RunManager:
    """Manages background scan tasks and WebSocket subscriber broadcasting."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._subscribers: dict[str, list[WebSocket]] = {}

    # ── WebSocket subscriber management ────────────────────────────────

    def subscribe(self, run_id: str, ws: WebSocket) -> None:
        """Register a WebSocket client for progress events."""
        self._subscribers.setdefault(run_id, []).append(ws)

    def unsubscribe(self, run_id: str, ws: WebSocket) -> None:
        """Remove a WebSocket client."""
        subs = self._subscribers.get(run_id, [])
        if ws in subs:
            subs.remove(ws)
        if not subs:
            self._subscribers.pop(run_id, None)

    async def _broadcast(self, run_id: str, msg: ProgressMessage) -> None:
        """Send a progress message to all subscribers of a run."""
        dead: list[WebSocket] = []
        for ws in self._subscribers.get(run_id, []):
            try:
                await ws.send_json(msg.model_dump())
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.unsubscribe(run_id, ws)

    # ── Scan lifecycle ─────────────────────────────────────────────────

    async def start_run(self, run_id: str, config: dict[str, Any]) -> None:
        """Spawn a background asyncio task to execute the scan."""
        task = asyncio.create_task(self._execute_scan(run_id, config))
        self._tasks[run_id] = task

    async def cancel_run(self, run_id: str) -> bool:
        """Cancel a running scan. Returns True if cancelled."""
        task = self._tasks.pop(run_id, None)
        if task and not task.done():
            task.cancel()
            async with self._session_factory() as session:
                from ziran.interfaces.web.models import Run

                run = await session.get(Run, uuid.UUID(run_id))
                if run:
                    run.status = "cancelled"
                    run.completed_at = datetime.now(UTC)
                    await session.commit()
            return True
        return False

    async def shutdown(self) -> None:
        """Cancel all active tasks on app shutdown."""
        for run_id in list(self._tasks):
            await self.cancel_run(run_id)

    def is_active(self, run_id: str) -> bool:
        """Check if a run has an active background task."""
        task = self._tasks.get(run_id)
        return task is not None and not task.done()

    # ── Internal scan execution ────────────────────────────────────────

    async def _execute_scan(self, run_id: str, config: dict[str, Any]) -> None:
        """Execute a scan campaign and update the database with results."""
        from ziran.interfaces.web.models import PhaseResultRow, Run

        # Mark run as running
        async with self._session_factory() as session:
            run = await session.get(Run, uuid.UUID(run_id))
            if not run:
                return
            run.status = "running"
            run.started_at = datetime.now(UTC)
            await session.commit()

        try:
            # Build adapter from target config
            target_url = config.get("target_url", "")
            protocol = config.get("protocol")
            adapter, _target_cfg = load_remote_adapter(target_url, protocol_override=protocol)

            # Build scanner
            attack_library = AttackLibrary()
            scanner = AgentScanner(adapter=adapter, attack_library=attack_library)

            # Build strategy
            strategy_name = config.get("strategy", "fixed")
            strategy = build_strategy(strategy_name, stop_on_critical=True)

            # Parse phases
            phase_names = config.get("phases")
            phases = [ScanPhase(p) for p in phase_names] if phase_names else None

            # Coverage
            coverage = CoverageLevel(config.get("coverage_level", "standard"))

            # Progress callback
            def on_progress(event: Any) -> None:
                msg = ProgressMessage(
                    event=event.event.value,
                    phase=event.phase,
                    phase_index=event.phase_index,
                    total_phases=event.total_phases,
                    attack_index=event.attack_index,
                    total_attacks=event.total_attacks,
                    attack_name=event.attack_name,
                    message=event.message,
                    extra=event.extra,
                )
                asyncio.get_event_loop().create_task(self._broadcast(run_id, msg))

            # Execute campaign
            result = await scanner.run_campaign(
                phases=phases,
                coverage=coverage,
                strategy=strategy,
                max_concurrent_attacks=config.get("concurrency", 5),
                encoding=config.get("encoding"),
                on_progress=on_progress,
            )

            # Persist results
            async with self._session_factory() as session:
                run = await session.get(Run, uuid.UUID(run_id))
                if run:
                    run.status = "completed"
                    run.completed_at = datetime.now(UTC)
                    run.total_vulnerabilities = result.total_vulnerabilities
                    run.critical_paths_count = len(result.critical_paths)
                    run.dangerous_chains_count = result.critical_chain_count
                    run.final_trust_score = result.final_trust_score
                    run.total_tokens = result.token_usage.get("total_tokens", 0)
                    run.result_json = result.model_dump(mode="json")
                    # Store graph state from last phase
                    if result.phases_executed:
                        run.graph_state_json = result.phases_executed[-1].graph_state

                    # Insert phase results
                    for i, pr in enumerate(result.phases_executed):
                        phase_row = PhaseResultRow(
                            run_id=uuid.UUID(run_id),
                            phase=pr.phase.value,
                            phase_index=i,
                            success=pr.success,
                            trust_score=pr.trust_score,
                            duration_seconds=pr.duration_seconds,
                            token_usage_json=pr.token_usage,
                            vulnerabilities_found=pr.vulnerabilities_found,
                            discovered_capabilities=pr.discovered_capabilities,
                            error=pr.error,
                        )
                        session.add(phase_row)

                    await session.commit()

            # Broadcast completion
            await self._broadcast(
                run_id,
                ProgressMessage(event="campaign_complete", message="Scan completed"),
            )

        except asyncio.CancelledError:
            logger.info("Scan %s cancelled", run_id)
        except Exception as exc:
            logger.exception("Scan %s failed", run_id)
            async with self._session_factory() as session:
                run = await session.get(Run, uuid.UUID(run_id))
                if run:
                    run.status = "failed"
                    run.error = str(exc)
                    run.completed_at = datetime.now(UTC)
                    await session.commit()

            await self._broadcast(
                run_id,
                ProgressMessage(
                    event="campaign_complete",
                    message=f"Scan failed: {exc}",
                ),
            )
        finally:
            self._tasks.pop(run_id, None)
