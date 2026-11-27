# Implementation Plan: attacker-LLM campaigns (TAP tree search, live crescendo)

**Branch**: `feat/128-attacker-loop` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Pydantic v2 (`CampaignConfig`), stdlib `asyncio` and
`json`; no new dependency. Reuses `PairExecutor` (attacker call, target call, result),
`CampaignBudget`, `goal_status` and the tactic session gate.

## Approach

1. `ziran/domain/entities/attack.py`: `ATTACKER_TACTICS = ("pair", "tap", "crescendo_live")`,
   `CampaignConfig`, `AttackVector.campaign`, a validator that rejects `campaign` on another
   tactic, and `_check_new_session` extended to the attacker tactics.
2. `ziran/application/attacks/library.py`: `campaign=data.get("campaign")`.
3. `ziran/application/attacks/pair.py`: `is_pair` reads `ATTACKER_TACTICS`; the phase timeout
   reads `campaign.timeout_seconds` for a campaign vector; the attacker call is split into
   `_send(system, text)` so the campaign modes share its ledger record; `_attempt` takes the
   prompts sent before (`sent`) for the scan metadata of a conversation.
4. New `ziran/application/attacks/campaign.py`: `CampaignExecutor(PairExecutor)` with
   `execute` (dispatch: `pair` to the PAIR loop), `_tap`, `_crescendo` and one `_node` step that
   asks the attacker, calls the target, scores the verdict, records turns and replies, and
   appends the node.
5. `ziran/application/agent_scanner/attack_executor.py`: dispatch `ATTACKER_TACTICS` to
   `CampaignExecutor`.
6. `ziran/application/agent_scanner/scan_cache.py`: a result with `campaign` evidence is not
   cached.
7. `ziran/application/attacks/tactics.py`: `TacticType.TAP` and `TacticType.CRESCENDO_LIVE`.
8. `examples/30-attacker-campaigns/`: a TAP and a live-crescendo scenario with a shell-sink goal,
   and a README. A row in `examples/README.md`.
9. `docs/concepts/attack-vectors.md`: a "TAP and live crescendo" section.

## Constitution check

- Hexagonal: the config is a domain entity; the executor is application code and imports no
  infrastructure (a pending reply is read by its `reason` attribute, as PAIR does).
- Type safety: Pydantic model, mypy strict.
- New scenarios are YAML (principle V).
- Tests: unit tests for the config, both modes, every bound and stop, the goal stop, the cassette
  repeat and the dispatch, and a scan through `AgentScanner`.
- Size: `scanner.py` unchanged; `attack_executor.py`, `pair.py` and `campaign.py` under 400.
- Unchanged: detectors, hybrid judge and prompts, `review_evidence`, role typing, tool aliases,
  `chain_patterns.yaml`.

## Test plan

`tests/unit/test_campaign_executor.py`: the example YAML loads through `AttackLibrary`; config
bounds and extra keys; `campaign` on a non-campaign tactic; acceptance 1 (TAP stops on
`goal_met` under 50,000 tokens, every node carries prompt, reply, score and pruning reason;
a small budget stops at `budget`); acceptance 2 (record, then replay through
`RecordReplayClient`, equal tree); one test per bound (`width`, `branching`, `depth`, `turns`,
`max_nodes`, timeout); stops on `success`, `exhausted`, `attacker_error`, `pending`; parse
errors; crescendo turns and conversation; PAIR still dispatched; `is_pair` and the phase
timeout; the cache refusal; a scan through `AgentScanner` with the attacker in the config.
