# Implementation Plan: blast radius per chain, demonstrated vs reachable, with what-if

**Branch**: `feat/091-blast-radius` | **Date**: 2026-11-23 | **Spec**: [spec.md](spec.md)
**Base**: `develop` @ 7006a23

## Summary

One new module walks the knowledge graph forward from a chain's last tool and its agents,
classifies what it reaches by role, and splits the nodes into demonstrated and reachable from
the campaign's recorded tool calls. `ResultBuilder` fills each chain's radius after the chain
analysis and writes one radius per last tool into the result.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13).
**Primary Dependencies**: Pydantic v2, NetworkX (already used), stdlib `collections.deque`. No
new dependencies.
**Storage**: none. The radius rides the scan result JSON.
**Testing**: `tests/unit/application/test_blast_radius.py` (new) plus the chain, scanner,
report and CI tests that read `dangerous_tool_chains`.

## Constitution Check

- Hexagonal architecture: `blast_radius.py` sits in the application layer's knowledge graph and
  imports only application and domain code. The models sit in the domain beside
  `DangerousChain`.
- Type safety: annotated, mypy strict clean; the radius is two Pydantic models.
- Simplicity: one breadth-first walk and one name rule; no flag. Reuses `tool_roles`,
  `tool_legs`, `tokens` and `canonical_tool_name`.

## Design

| File | Change |
|------|--------|
| `ziran/application/knowledge_graph/blast_radius.py` (new) | `blast_radius`, `is_external`, `FOLLOWED`, `EXTERNAL`, `MAX_LISTED` |
| `ziran/domain/entities/capability.py` | `BlastReach`, `BlastRadius`; `DangerousChain.blast_radius` |
| `ziran/domain/entities/phase.py` | `CampaignResult.blast_radius` (one radius per last tool) |
| `ziran/application/agent_scanner/result_builder.py` | `_fill_blast_radius`: one walk per last tool; chain dicts exclude the radius |
| `specs/086-flat-agent-chains/spec.md` | the walker table gains the blast radius row |

## Verification

- Red: the new test file on a `git archive` copy of base fails at collection (no
  `blast_radius` module); before `ResultBuilder` was wired, the three scan tests failed.
- Green: the new file, `test_scanner_size.py` and the tests of the chain consumers, under
  `timeout -s KILL 120`.
- Size and time at 10, 100 and 101 tools and 20,000-character ids, base against head (spec).
- `benchmarks/ground_truth/run.py` on base and head: every component unchanged.
