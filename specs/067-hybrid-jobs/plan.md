# Implementation Plan: the hybrid's three model jobs on the seam

**Branch**: `feat/067-hybrid-jobs` | **Date**: 2026-11-12 | **Spec**: [spec.md](spec.md)

## Summary

One new module, `ziran/application/hybrid/jobs.py`, holds the three jobs: each a renderer, a
parser for the registered reply form, a merge rule, and an async entry point over `decide()`.
`provenance.py` gains `_kinds`, the one extraction `_evidence` and `evidence_values` both read.
The seam's `decide()` passes the unit to the parse and accepts a parse's own pending cause.
`request_key` takes an optional repeat index. Two settings join `DetectorThresholds`, with CLI
options on `scan` and `audit`. `agent_chains` passes `typed` and `role_overrides` to #492's
analyzer.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2, stdlib `hashlib`/`json`/`re`/`unicodedata`; reuses
`decide`, `RecordReplayClient`, `ToolChainAnalyzer(typed=True)` (#492), the SA001 patterns. No
new dependencies.
**Storage**: prompt files in the package; a test fixture rendered by the spike's own code
(`tests/fixtures/hybrid/spike_render.py`, run with `python -I` on a `git archive` of
ziran-paper at e4b2025).
**Testing**: pytest, `@pytest.mark.unit`; replies through `RecordReplayClient` from synthetic
`outcomes.jsonl` files.

## Constitution Check

- Hexagonal: the jobs are application code over the port `BaseLLMClient`; no adapter is added.
  PASS
- No live call: only `RecordReplayClient` is used in tests; spec 064's import guard still finds
  no importer of the seam under `ziran/`. PASS
- Deterministic mode: defaults 0.0 and off; benchmark and detection regression unchanged. PASS

## Stacking

The branch merges #492 (`feat/066-v2-role-typing`) for `typed=True` and `role_overrides`. It
merges after #492.
