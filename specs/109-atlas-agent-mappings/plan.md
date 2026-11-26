# Implementation Plan: MITRE ATLAS agent techniques and OWASP Agentic ASI08 to ASI10 mappings

**Branch**: `feat/109-atlas-agent-mappings` | **Date**: 2026-11-26 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ f533d8e

## Summary

Add twelve members to `AtlasTechnique` with their names in `ATLAS_TECHNIQUE_DESCRIPTIONS` and
tactics in `ATLAS_TECHNIQUE_TO_TACTIC`. Append the ids to the `atlas_mapping` lists of the
vectors in the spec's mapping table. Change the multi-agent entry of `AGENTIC_DEFAULTS` and add
`owasp_agentic_mapping` to eight vector YAMLs. Regenerate the coverage outputs and update the
docs that quote the counts.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13).
**Primary Dependencies**: Pydantic v2, PyYAML. No new dependencies.
**Storage**: vector YAML files; `benchmarks/results/baseline.json`.
**Testing**: pytest. New `tests/unit/test_atlas_agent_techniques.py`; the existing ATLAS enum,
coverage-script, OWASP Agentic and scanner-size tests.

## Constitution Check

- Hexagonal architecture: the enum and its tables stay in the domain; the default table stays
  in the application loader.
- Type safety: enum members and typed dict entries; mypy strict.
- Tests: test first; `@pytest.mark.unit` on each test.
- Extensibility: mappings are YAML (principle V); no code path changes.
- Simplicity: no new function, flag or file besides the test and the spec.

## Design

- Enum members sit in the enum's tactic sections (Persistence, Discovery, AI Attack Staging,
  Exfiltration) with a comment naming release v2026.10, as `AML.T0105` and `AML.T0142` do.
- `AML.T0110.001` and `AML.T0118` are enum members with no vector. The coverage JSON lists them
  under `uncovered_techniques`; the gate checks only `AGENT_SPECIFIC_TECHNIQUES`, which is
  unchanged, so it still passes.
- The test holds one expected vector set per technique and asserts
  `get_attacks_by_atlas(technique)` equals it, so an extra tag fails as well as a missing one.
- YAML edits only append ids to the inline `atlas_mapping` lists, kept sorted where the list was
  sorted.
- `benchmarks/generate_all.py` rewrites `benchmarks/README.md` and
  `docs/reference/benchmarks/coverage-comparison.md`; `regression_check.py --update-baseline`
  rewrites `baseline.json`. The regenerated detection F1 lines in `coverage-comparison.md`
  differ from the committed doc for reasons unrelated to this change, so they are left as
  they were.

## Rollback

Revert the merge commit. The change only adds enum members and list entries, so scan JSON
written by this version loads in an older version only if it carries no new id; older JSON
loads here.
