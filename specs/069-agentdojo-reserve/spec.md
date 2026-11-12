# Feature Specification: the AgentDojo reserve set and the `run.py --paper` guard check

**Feature Branch**: `g11-agentdojo-reserve`
**Created**: 2026-11-12
**Status**: Active
**Base**: `develop` @ b230c50 (spec 065, the fresh set, merged in #493)
**Input**: plan item G11-AGENTDOJO-RESERVE (ziran-paper goal G-11, tier smart). The include rule
is `rules.reserve` in ziran-paper `prereg/g11-intake/agentdojo.json` on `main`. The guard contract
is the deviation "the fresh and reserve run guards" in `prereg/patch-protocol.md` section 16 and
`study/scripts/g11_run_guard.py`, both read at ziran-paper #130 head `3194f7d`.

## The item in my own words

The B1 and B2 bars bind to the AgentDojo reserve run alone. The harness had no way to read that
set: no benchmark key, no include rule, and no cell that names the attack, which section 7
reports per reserve cell (model folder and attack). The protocol also says no fresh or reserve
log is opened unless the paper's run guard admitted the attempt. ziran-paper's guard writes and
commits an `aborted` line in the set's use log before the fetch. ziran's harness must check that
line before it opens `--data`, for the fresh set and the reserve set.

- (a) A new benchmark `agentdojo_reserve` admits a run log when its model folder is defended
  (`Meta-SecAlign-70B`, or a folder that ends in `-repeat_user_prompt`,
  `-spotlighting_with_delimiting`, `-tool_filter` or `-transformers_pi_detector`) and its attack
  is anything but `none`. Other paths are counted as outside. The rule's second clause (logs at
  head absent at the pin) is empty, since head is the pin.
- (b) Each reserve unit carries the cells of an AgentDojo unit plus `attack`, the attack folder.
  Rows pass `check_row` unchanged. Its primary predictor is `deterministic`, as for the fresh set.
- (c) `agentdojo_fresh` and `agentdojo_reserve` need `--paper <ziran-paper checkout>`. After the
  pins resolve and before the output folder or any data file is touched, `run.py` refuses with
  exit 2 and writes nothing unless the set's use log (`study/results/g11_fresh_uses.jsonl` or
  `study/results/g11_reserve_uses.jsonl`):
  - is a regular file, not a link, and equals its blob at the checkout's HEAD;
  - holds JSON objects only, at least one, and no line with `status` `scored`;
  - ends in a line with `status` `aborted`, a `pin` that names one of the run's `--pin` names, a
    `ziran_sha` equal to that pin's resolved commit, and a `sha256` equal to that of the
    manifest's run-log paths, sorted and joined by newlines.

Acceptance (the plan's): given synthetic reserve-shaped logs, the loader's rows carry the model
folder and attack cells and pass `check_row`; given no authorisation, the run refuses before it
reads any data file.

## Requirements

- FR-001: `mapping.agentdojo_reserve_admitted` implements `rules.reserve`; the dev, fresh and
  reserve rules admit disjoint paths.
- FR-002: `mapping.agentdojo_reserve_units` adds the `attack` cell; `collect` registers
  `agentdojo_reserve` with primary `deterministic`.
- FR-003: `run.require_admitted` performs the checks of (c) and is called before the output
  folder is created and before the manifest's files are loaded.
- FR-004: The harness does not import or re-run ziran-paper's guard. It reads the log the guard
  commits, by the contract section 16 states for `run.py --paper`.
- FR-005: Tests use synthetic logs and synthetic use logs only.

## Assumptions

- "A `ziran_sha` equal to the running commit" means the commit of the pin the line names (the
  guard writes the tag's commit there), not the harness commit. Overturned if #130 says the
  harness commit.
- The log must equal its blob at HEAD. The contract asks only for the line checks; this extra
  check refuses a work tree whose scored line was cut. The guard's own run commits the line
  before it returns, so an admitted run always passes it. Overturned if the runbook runs the
  harness against an uncommitted log.
- "The manifest's run-log paths" are the manifest entries that match the AgentDojo run-log path
  rule, so the licence file is left out. Overturned if G11-SCORE's fetch writes another file
  into the manifest that the guard also hashes.
- `--paper` given with another benchmark is ignored, since no guard covers those sets.
- The reserve set's primary is `deterministic`, as for the fresh set; section 6 names no other.

## Out of scope

- The fetch of the reserve files and the reserve run itself (G11-SCORE's runbook).
- An `attack` cell on the dev or fresh rows; dev outputs stay byte-for-byte as registered.
