# Tasks: attacker-LLM campaigns (TAP tree search, live crescendo)

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

## Phase 1: tests first

- [x] T001 Write failing tests for the config, both modes, every bound and stop, the goal stop,
  the cassette repeat, the dispatch and the cache (`tests/unit/test_campaign_executor.py`); run
  red.

## Phase 2: model and loader

- [x] T002 `ATTACKER_TACTICS`, `CampaignConfig`, `AttackVector.campaign` and its validators
  (`ziran/domain/entities/attack.py`); `campaign` in the loader (`library.py`).

## Phase 3: executor

- [x] T003 `is_pair`, the campaign timeout, `_send` and `sent` in `pair.py`.
- [x] T004 `CampaignExecutor` with the TAP and live-crescendo modes
  (`ziran/application/attacks/campaign.py`).
- [x] T005 Dispatch in `attack_executor.py`; cache refusal in `scan_cache.py`; `TacticType`
  members, and the tactic count in `tests/unit/test_expanded_tactics.py`.

## Phase 4: scenarios, docs and gates

- [x] T006 Example scenarios and README (`examples/30-attacker-campaigns/`), row in
  `examples/README.md`.
- [x] T007 Docs section in `docs/concepts/attack-vectors.md`.
- [x] T008 ruff check, ruff format, mypy strict, touched tests on Python 3.11, 3.12 and 3.13;
  size test; mutants on the bounds.

## Phase 5: gate round 1

- [x] T009 Merge `origin/develop` (#601); keep the campaign dispatch with `self.attacker`.
- [x] T010 Budget check counts the running vector's target tokens (campaign and PAIR), tested
  with a target that reports 5,000 tokens per reply on a 50,000 cap, and through a scan.
- [x] T011 `_parse_prompt` treats a huge integer or deep nesting as a parse error; tested on
  3.11 for TAP, crescendo_live and PAIR with an earlier success and its tokens kept.
- [x] T012 Early stops without a success are unmeasured with `goal_met: null`; finite, capped
  timeouts; stored prompts capped at 2,000 characters; node count in the docs; attacker-vector
  wording in the not-run warning, `--attacker-model` help and the skip errors.
