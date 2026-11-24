# Feature Specification: stop on critical only from exploitation_setup onwards

**Feature Branch**: `fix/stop-on-critical-late-phases`
**Created**: 2026-11-24
**Status**: Active
**Plan item**: A-STOP-CRIT-RECON (goal G-a)

## The promise in our own words

A live scan with `stop_on_critical` on ended a seven-phase campaign after reconnaissance,
because three supply-chain probes (`mcp_supply_chain_typosquat`,
`mcp_supply_chain_dependency_confusion`, `sc_backdoored_lora_adapter`) scored critical. The
later phases never ran. A critical finding in a probing phase says the agent is weak; it is
not a reason to skip the phases that test how far the weakness reaches.

`stop_on_critical` now stops only on a critical finding from `exploitation_setup`, `execution`,
`persistence` or `exfiltration`. The set is `STOP_ON_CRITICAL_PHASES` in
`ziran/domain/entities/phase.py`, next to `ScanPhase`. Criticals from `reconnaissance`,
`trust_building`, `capability_mapping` and `vulnerability_discovery` stay in the result and the
campaign goes on. The default stays on. The scanner builds `CampaignContext.critical_found`
for every strategy, so `FixedStrategy`, `AdaptiveStrategy` and `LLMAdaptiveStrategy` agree with
no change of their own; `build_strategy` and the multi-agent scanner only pass the flag on.

## Acceptance scenarios

1. **Given** a critical finding in reconnaissance (or any early phase), **When** the scan runs
   with `stop_on_critical` on, **Then** every later phase runs and the finding is kept.
2. **Given** a critical finding in `exploitation_setup` or `execution`, **When**
   `stop_on_critical` is on, **Then** the campaign ends after that phase.
3. **Given** `stop_on_critical` off, **When** any critical lands, **Then** every phase runs.

## Requirements

- FR-001: `STOP_ON_CRITICAL_PHASES` is the one place that names the set.
- FR-002: `AgentScanner._has_critical_finding` is False for a phase outside the set.
- FR-003: `run_campaign(stop_on_critical=True)` stays the default.

## Assumptions

- `persistence` and `exfiltration` count as "later phases" (the item says exploitation_setup
  or later).
- The scanner is the one place to filter: both strategies and the LLM strategy read the
  context flag it builds. Overturned if a strategy is ever driven with a hand-built context in
  production code.
- `CHANGELOG.md` is written by release-please from commit messages, so no manual entry.
- `scanner.py` is at 749 of 750 lines after the change; no further growth fits.
