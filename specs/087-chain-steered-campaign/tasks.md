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

## Phase 4 - Fix round 1 (gate findings)

- [x] T012 `_resource`: guard an empty `examples` list (IndexError aborted the campaign); a
      campaign test with `"examples": []`. Target text (resource, tool names) is used only when
      one line, at most 100 characters and brace-free; a brace-heavy default stays bounded.
      A `steer` test pins that only vectors in the phase list come back.
- [x] T013 Secret check on normalised text with the chain's tool and resource names removed;
      payloads naming a secret are skipped, not rewritten; the spellings the gates listed.
- [x] T014 Library test over every family (six-tool agent, five exfil chains into
      `http_request`, `read_config` + `update_permissions`) that fails with the guard off.
- [x] T015 Tests: a cap keeps the chain vectors and `ran` leaves out the cut one; the strategy
      context in a real campaign carries the chains and the boost picks the execution phase.
- [x] T016 URL hosts and mail domains rewritten to `reports.example.invalid`.

## Phase 5 - Fix round 2 (gate findings)

- [x] T017 A schema default naming a secret is not the resource; only tool names are left out
      of the check. Tests: `~/.aws/credentials`, `config/secrets.yaml`, a direct `_render`.
- [x] T018 The host map applies to success and failure indicators and the description; an
      end-to-end test where an agent renders the rewritten `de_markdown_link` link and it scores.
- [x] T019 Header family (authorization and auth headers, cookies, bearer) in the pattern; the
      library test pins the reviewed chosen ids per agent and coverage.
- [x] T020 Tests for the source name's `_plain` check and the "the first tool" / "the last
      tool" fallback wording.
