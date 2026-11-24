# Plan: stop on critical only from exploitation_setup onwards

1. `ziran/domain/entities/phase.py`: add `STOP_ON_CRITICAL_PHASES` (frozenset) after `CORE_PHASES`.
2. `ziran/application/agent_scanner/scanner.py`: import it; `_has_critical_finding` returns
   False for a phase outside it (3 lines; 749 of 750).
3. Tests in `tests/unit/test_stop_on_critical_phases.py` with a stubbed `PhaseExecutor.execute`:
   Fixed and Adaptive strategies, each early phase, `exploitation_setup`, `execution`,
   flag off, default on, the set itself.

Rollback: revert the commit; the old stop-on-any-critical behaviour returns.
