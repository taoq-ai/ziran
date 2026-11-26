# Tasks: attacker-LLM campaigns (TAP tree search, live crescendo)

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

## Phase 1: tests first

- [ ] T001 Write failing tests for the config, both modes, every bound and stop, the goal stop,
  the cassette repeat, the dispatch and the cache (`tests/unit/test_campaign_executor.py`); run
  red.

## Phase 2: model and loader

- [ ] T002 `ATTACKER_TACTICS`, `CampaignConfig`, `AttackVector.campaign` and its validators
  (`ziran/domain/entities/attack.py`); `campaign` in the loader (`library.py`).

## Phase 3: executor

- [ ] T003 `is_pair`, the campaign timeout, `_send` and `sent` in `pair.py`.
- [ ] T004 `CampaignExecutor` with the TAP and live-crescendo modes
  (`ziran/application/attacks/campaign.py`).
- [ ] T005 Dispatch in `attack_executor.py`; cache refusal in `scan_cache.py`; `TacticType`
  members.

## Phase 4: scenarios, docs and gates

- [ ] T006 Example scenarios and README (`examples/30-attacker-campaigns/`), row in
  `examples/README.md`.
- [ ] T007 Docs section in `docs/concepts/attack-vectors.md`.
- [ ] T008 ruff check, ruff format, mypy strict, touched tests on Python 3.11, 3.12 and 3.13;
  size test; mutants on the bounds.
