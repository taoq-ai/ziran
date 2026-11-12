# Implementation Plan: V2 role typing as an added chain class

**Spec**: [spec.md](spec.md) | **Tasks**: [tasks.md](tasks.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13) + Pydantic v2, stdlib `re`; no new dependencies.
Reuses `READ_VERBS` and `tokens` from `ziran/application/detectors/provenance.py` (spec 063) and
`canonical_tool_name` from `tool_aliases.py`.

## Changes

| File | Change |
| --- | --- |
| `ziran/application/knowledge_graph/role_typing.py` | new: the V2 lists, `tool_roles`, the three typed vulnerability types |
| `ziran/application/knowledge_graph/chain_analyzer.py` | `typed` and `role_overrides` keywords; `_find_typed_chains` after the table's chains |
| `ziran/domain/entities/capability.py` | `DangerousChain.typed: bool = False` |
| `tests/unit/test_role_typing.py` | name rules, overrides, typed chains, acceptance 4 and 5 |
| `tests/unit/test_role_typing_probe_parity.py` | the probe's code as oracle; literal and seeded parity |
| `tests/integration/test_chain_study_v1_equality.py` | study-v1 equality on the chain fixtures |
| `tests/fixtures/chains/study_v1_chains.json` | study-v1's chains, written from the tag |

The 126-pattern table, its first-match order and the direct, indirect, cycle and unrestricted
execution searches are unchanged. Typed chains are found after them and enter the same
de-duplication, scoring and sort.

Frozen and untouched: `ziran/domain/tool_classifier.py`, `ziran/application/detectors/refusal.py`,
`ziran/application/detectors/llm_judge.py`, `ziran/domain/entities/claude_code.py`
(`git diff --quiet study-v1 -- <the four paths>` exits 0).

## The study-v1 fixture

Written from the tag, never from this branch:

```bash
git -C <ziran> archive 32281c77b057a360d29f3343f91b248430f84475 | tar -x -C <scratch>/v1
cd <scratch>/v1 && PYTHONPATH=<scratch>/v1 <worktree>/.venv/bin/python -P v1_chains.py out.json
```

`v1_chains.py` asserts that `ziran` loads from the export, then writes, cycles off, the chains
(`tools`, `risk_level`, `vulnerability_type`, `chain_type`, `graph_path`, `risk_score`) of:

- each of the 22 agents of `benchmarks/ground_truth/agents`, on the benchmark's complete graph
  (`_build_graph_for_agent`): 36 chains;
- a two-tool agent for each of the 126 pattern pairs, in table order: 131 chains.

`git diff --stat 32281c77 HEAD -- ziran/application/knowledge_graph ziran/domain
benchmarks/ground_truth/agents benchmarks/ground_truth/run.py` is empty at the base, so the fixture
is the code and data as at study-v1.

## Parity with the dev probe

`tests/unit/test_role_typing_probe_parity.py` holds the probe's lines 69 to 91, 94, 111 to 115 and
272 to 284 between `# fmt: off` and `# fmt: on`. With blank lines dropped they are byte-equal to
`git show f80204a:study/scripts/g10_dev_probe.py | sed -n '69,91p;94p;111,115p;272,284p'`.

- The lists ziran uses equal the oracle's literals.
- `tool_roles` equals the oracle's roles, restricted to V2 and with `high` named `high_impact`, on
  25 fixed names (Claude Code ids, permission rules, MCP ids, LangChain aliases, blanks) and 3,000
  seeded names from the lists' words in snake, kebab, dotted, spaced, CamelCase and MCP forms.
- On 150 seeded agents of two to five such tools, the typed pairs equal the oracle's V2 typed
  pairs minus the pairs the table reports.

On the 13 dev-split agents of ziran-paper's `data/ground_truth_split.json` the patched analyzer
gives the probe's committed `agents_with_chain` for study-v1 (safe 2 of 7, vulnerable 4 of 6) and
V2 (5 of 7, 6 of 6). Parity on the AgentDojo dev tools is unmeasured here: those names stay in
ziran-paper.

## Benchmarks

With `typed` off (the default) `benchmarks/regression_check.py` reports no change from the
baseline, and `benchmarks/ground_truth/run.py` gives the base numbers: chain analyzer TP 13, FP 0,
FN 7; scenario verdict TP 30, FP 3, FN 0. With typed chains on, the scenario verdict's FP is 18
(spec, Assumptions 1).
