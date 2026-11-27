# Feature Specification: attacker cassette for `ziran scan`

**Feature Branch**: `feat/132-campaign-cassette`
**Created**: 2026-11-27
**Status**: Draft
**Input**: plan item F-CAMPAIGN-CASSETTE (goal G-f, tier light). Builds on spec 128 (campaign
executor), spec 127 (`--attacker-model`) and the spec 064 record-replay seam.

## The item in my words

A campaign tree can be replayed offline today only through test wrappers. `ziran scan
--attacker-cassette FILE` gives the CLI the same: with `--attacker-model` it records each
attacker reply as a spec 064 outcome row; without it, and with an existing FILE, it replays the
rows with no attacker client and no key. A request with no stored reply comes back pending and
the vector stops as unmeasured (spec 128).

**Acceptance.** Given a scan recorded with `--attacker-cassette`, when it reruns with the same
cassette and no attacker, then the campaign tree is identical.

## Design

`ziran/infrastructure/llm/attacker_cassette.py` holds `Recorder` and `Cassette` (moved from
`tests/unit/test_campaign_executor.py`). The reply is keyed by the system text, the user text
and a fixed client label, not the model id, so a replay needs no model; each row carries the
model id so the evidence reads the same. The file never holds a key. `Recorder` rewrites the
whole file through a temporary file and `replace` (the `CheckpointManager.save` pattern). A path
or parent that is a symlink is refused, as `RecordReplayClient` refuses its request file.

## Assumptions

- A non-JSON attacker reply is stored as an `unparsed` row and replays as pending.
- Recording into an existing cassette keeps its rows and adds or overwrites by key.
- The rows hold prompts, so the file is mode 0600.
