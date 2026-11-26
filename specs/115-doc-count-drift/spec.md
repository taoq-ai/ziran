# Spec 115: Doc count drift test

Status: Active

## Why

Hand-written counts in the docs drift when vectors are added (695 after #586 to #588). Nothing caught it.

## What

One unit test, `tests/unit/test_doc_counts.py`, compares anchored phrases in `README.md`, `docs/reference/attack-library.md` and `docs/reference/benchmarks/atlas-mapping.md` (total vectors, YAML files, categories, ATLAS covered and enum counts, the agent-technique rows) with `AttackLibrary` and the `vectors/` folder. It fails naming each stale doc and line.

Historical entries in `docs/community/roadmap.md` carry no live count; the test fails on one that does.

## Scenarios

- A doc count differs from the library: the test names the doc and line.
- A roadmap entry states a vector or technique count: the test names the line.
- A doc phrase is reworded so the anchor is missing: the test fails with the phrase.
