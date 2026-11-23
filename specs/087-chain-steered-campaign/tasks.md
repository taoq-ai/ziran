# Tasks: chains found at discovery steer the campaign

Base: `origin/develop` @ ad2b626. Branch `feat/087-chain-steered-campaign`. Test first: T001 to
T003 run red before T004.

## Phase 1 - Tests

- [x] T001 `tests/unit/application/test_chain_targeting.py`: family table, plan (harmful_task,
      protocol, fit order, one chain per vector, cap), rendering (tool names, path, no secret
      words), `steer` (front, stable, unchanged with no chains), `AdaptiveStrategy` boost,
      `LLMAdaptiveStrategy` prompt line, context fields at the phase executor, report tables,
      100-tool timing.
- [x] T002 `tests/unit/test_langgraph_adapter.py`: flat LangChain agent with a scripted model,
      execution phase, fixed strategy, concurrency 1: chain vectors first, marked as run, the
      first carries the `http_request` call; chain ids are `tool_<name>`; an agent with no chain
      runs in library order.
- [x] T003 Run T001 and T002 red.

## Phase 2 - Implementation

- [x] T004 `ziran/domain/entities/phase.py`: `ChainTarget`, `CampaignResult.chain_targets`.
- [x] T005 `ziran/application/strategies/protocol.py`: `dangerous_chains`, `chain_vectors`.
- [x] T006 `ziran/application/agent_scanner/chain_targeting.py`: table, `plan_steering`,
      rendering, `steer`, `campaign_context`.
- [x] T007 `scanner.py`: helper for the two context blocks first, then the steering wiring.
- [x] T008 `phase_executor.py`, `result_builder.py`.
- [x] T009 `adaptive.py`, `llm_adaptive.py`.
- [x] T010 `reports.py`, `html_report.py`.

## Phase 3 - Checks

- [x] T011 Touched tests and `test_scanner_size.py` green; ruff, ruff format, mypy clean.
