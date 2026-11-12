# Implementation Plan: prompt registry and record-and-replay model client

**Branch**: `feat/064-llm-seam` | **Date**: 2026-11-12 | **Spec**: [spec.md](spec.md)

## Summary

Three small modules and their tests. `ziran/application/hybrid/prompts.py` loads prompt files by
job and version. `ziran/infrastructure/llm/replay_client.py` holds `request_key`,
`PendingResponse` and `RecordReplayClient`. `ziran/application/hybrid/__init__.py` holds
`routed()` (the `hybrid_route_share` order) and `decide()`, which keeps the deterministic verdict
for every pending or unparsable reply. Nothing existing imports them.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2, stdlib `hashlib`/`json`/`re`/`decimal`; reuses `BaseLLMClient`. No new dependencies.
**Storage**: one caller-named `*.requests.jsonl` per record run; ziran-paper's `outcomes.jsonl` read in replay; neither committed.
**Testing**: pytest, `@pytest.mark.unit`. Placeholder prompts under
  `tests/fixtures/hybrid_prompts/`. Sockets and processes blocked by monkeypatch in the record
  test.

## Constitution Check

- Hexagonal: the client is an infrastructure adapter behind `BaseLLMClient`. The application
  module imports `BaseLLMClient` and `PendingResponse` from infrastructure, as
  `detectors/llm_judge.py` already imports `BaseLLMClient`. PASS
- Type safety: annotated throughout, Pydantic models for `Prompt`, `PendingResponse` and
  `HybridResult`, mypy strict. PASS
- Tests: unit tests for each acceptance scenario and edge case. PASS
- Async-first: `complete()` and `decide()` are async. The request file append is a small local
  write, as `checkpoint.py` does. PASS
- Simplicity: no new dependency, no CLI, no renderer; three modules. PASS

## Design

| Piece | Where | Notes |
| --- | --- | --- |
| `Prompt`, `load`, `PROMPTS` | `application/hybrid/prompts.py` | job matches `[a-z][a-z0-9_]*`, version is an int of 0 or more; reads `<root>/<job>/v<N>.md` |
| `request_key` | `infrastructure/llm/replay_client.py` | sha256 over four length-prefixed UTF-8 parts |
| `PendingResponse` | same | an `LLMResponse` with `content=""` and a `reason` |
| `RecordReplayClient` | same | `record_to=` or `replies=`, one of the two; `complete(messages, job=, unit=, prompt=)` |
| `routed`, `decide`, `HybridResult` | `application/hybrid/__init__.py` | share in `[0, 1]`, floor of `share * n` by `Decimal`, sha256 order |

The request line's form is the one `hybrid_send.load_requests` reads: exactly `key`, `job`,
`unit`, `text`, with `unit` matching its `UNIT` pattern and `text` non-blank.

## Risks

- A caller that reads `PendingResponse.content` as a verdict. `decide()` is the one path that
  turns replies into verdicts, and it checks the type first.
- A prompt edited in place. The base-branch test fails on it; the CI test job fetches `develop`.
