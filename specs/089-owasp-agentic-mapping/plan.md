# Implementation Plan: map attack vectors to the OWASP Top 10 for Agentic Applications

**Branch**: `feat/089-owasp-agentic-mapping` | **Date**: 2026-11-23 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ 3b0589a

## Summary

Add the `OwaspAgenticCategory` enum and descriptions beside `OwaspLlmCategory`. Add the field to
`AttackVector` and `AttackResult`. In `AttackLibrary._parse_vector`, read the YAML key and fall
back to a module-level default table keyed by `AttackCategory`. Add
`lint_owasp_agentic_coverage` next to `lint_atlas_coverage`. Copy the field at each
`owasp_mapping=attack.owasp_mapping` site in the executors. Join the Agentic ids into the PoC
generator's OWASP string through one helper. Set overrides in five vector YAML files. Rewrite the
docs table.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13).
**Primary Dependencies**: Pydantic v2, PyYAML. No new dependencies.
**Storage**: none. Vector YAML files gain an optional key.
**Testing**: pytest. A new `tests/unit/test_owasp_agentic_mapping.py`; the size budget test
`tests/unit/application/test_scanner_size.py`.

## Constitution Check

- Hexagonal architecture: the enum lives in the domain; the default table lives in the
  application loader, which already turns YAML into domain models.
- Type safety: typed enum and fields; mypy strict.
- Tests: test first; `@pytest.mark.unit` on every test.
- Extensibility: overrides are YAML, not code (principle V).
- Simplicity: one dict, one lint method, one formatting helper; no new option or flag.

## Design

- Default table `AGENTIC_DEFAULTS: dict[AttackCategory, list[OwaspAgenticCategory]]` in
  `library.py`, covering all eleven categories. `test_every_category_has_a_default` fails when a
  new category has no entry; at load the vector would raise `KeyError`, which the loader records
  as a load error and skips the vector.
- `dynamic_vectors/generator.py`: `generate` sets the category default on each vector it
  returns.
- `mcp_server_surface/scoring.py`: `score_reply` copies the field, and the
  `build_campaign_result` artifacts list it beside `owasp_mapping`.
- `_parse_vector`: `[OwaspAgenticCategory(o) for o in data.get("owasp_agentic_mapping") or []]
  or list(_AGENTIC_DEFAULTS[category])`.
- `attack_executor.py` (384 lines): four one-line additions, 388 after.
- `tactics.py` has three `owasp_mapping` copy sites; it builds multi-turn results for the scan,
  so it takes the field too.
- PoC generator: `_owasp_ids(result)` returns the joined LLM and Agentic ids or `N/A`, used at
  its four OWASP lines.

## Rollback

Revert the merge commit. The field is additive with an empty default, so older scan JSON still
loads, and newer JSON loads in this version.
