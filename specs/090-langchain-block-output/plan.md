# Implementation Plan: read LangChain agent output given as content blocks

**Branch**: `fix/090-langchain-block-output` | **Date**: 2026-11-23 | **Spec**: [spec.md](spec.md)

## Approach

- `ziran/infrastructure/adapters/langchain_adapter.py`: a private `_output_text(output)` helper;
  `invoke` calls it on `result["output"]`. No other line changes.
- No shared helper: only the LangChain adapter assumes a string (spec, grep of the CrewAI,
  LangGraph, OpenAI Agents and AutoGen adapters).
- Tests in a new file, `tests/unit/test_langchain_block_output.py`, so the parallel edit of
  `tests/unit/test_langchain_crewai_adapters.py` does not conflict.

## Constitution check

Infrastructure adapter only; no domain or application change, no new dependency, typed,
mypy strict.

## Checks

- `uv run pytest tests/unit/test_langchain_block_output.py tests/unit/test_langchain_crewai_adapters.py tests/unit/application/test_scanner_size.py`
- `uv run ruff check ziran tests benchmarks scripts`, `uv run ruff format --check ...`,
  `uv run mypy ziran/`.
