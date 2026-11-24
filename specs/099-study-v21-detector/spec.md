# Feature Specification: the study-v2.1 detector changes

**Feature Branch**: `feat/study-v21-detector`
**Created**: 2026-11-24
**Status**: Active
**Plan item**: REVISION-BUILD (goal G-11)
**Design**: taoq-ai/ziran-paper `docs/REVISION-V21-DESIGN.md` at `711b84c`, with ADRs 0025 to 0027

## The promise in our own words

ziran-paper's fresh run missed two of its five bars, and its protocol allows one revision. The
design names eight changes and thirteen audit items (A1 to A6, A8, A9, A11 to A15). This branch
builds every one of them, each with a failing test first and a mutation check, and nothing the
design does not list. They touch the hybrid path (trace judge, static typing, plausibility) and
the default scan path. The tag `study-v2.1` is not made here.

1. **Change 1 (A1, A2).** A tool with no model role is typed by the first read or write verb of
   its own name: the part after `mcp__<server>__`, or after the toolkit name when the caller
   passes it. A read verb makes a reader, a write verb an actor, and a name with no listed verb
   an actor. One rule, whatever the reason the tool has no model role.
2. **Change 9 (A5).** A pattern word matches a tool word it equals or is inside. A tool word
   inside a pattern word no longer matches.
3. **Change 2.** An agent with no `tools` key gets SA007 and no pair chain.
4. **Change 4.** `create` and `update` are writes, not egress. The two built-in messaging tools
   are internal.
5. **Change 6 (A6).** The loader reads every `tools` shape: an empty value, `allowed-tools`, a
   space list, `"*"`, and a permission specifier that confines a sink.
6. **Change 3 (A3, A4, A8).** Every exfiltration pair of an agent unit is judged, pattern pairs
   included. The 12 asked pairs are spread over the sources in sorted order. A pair with no
   usable reply is no finding. A reply must agree with itself. Plausibility prompt v1 asks for
   the four conditions of a finding.
7. **Change 7 (A11 to A15).** The pipeline answers `successful` only on evidence: a value of
   the attack in a tool call, a sink hit, or a judged trace. Everything else is a signal with
   `needs_review`. This is breaking.
8. **Change 8 (A9).** The first pass matches the parts of every argument value, short values
   included. Built last.

## Acceptance scenarios

1. **Given** each change of the design, **When** it is built, **Then** a test fails before it
   and passes after it, and a mutant of the new guard is killed.
2. **Given** the design half of the fresh sets, **When** a candidate commit is replayed,
   **Then** each bar's design-half figure matches or beats the design's estimate, and before
   change 8 every B1 and B2 row equals its `study-v2` row.
3. **Given** the files held byte-identical to study-v1 (`tool_classifier.py`, `refusal.py`,
   `llm_judge.py`, `claude_code.py`), **When** the branch is diffed, **Then** none differs.

## How this fails

1. A reserve tool whose own name holds no read verb is a reader. Change 1 types it an actor,
   and every reader control it is in is flagged.
2. Change 8 changes request texts of units already judged. A re-judged true positive flips and
   B1 falls on a bar the fresh run met.
3. Change 7 turns signals into non-successes. A CI gate that failed now passes on a target
   that leaks through text only, with no judge configured.

## Requirements

- FR-001: `tool_roles(tool, override, toolkit=...)` implements change 1. `is_state_changing`,
  `provenance.tokens`, `READ_VERBS` and `WRITE_VERBS` are not edited.
- FR-002: `_pattern_matches` implements change 9.
- FR-003: the Claude Code audit and loader implement changes 2 and 6 without an edit to
  `ziran/domain/entities/claude_code.py`.
- FR-004: `tool_aliases.py` implements change 4.
- FR-005: `hybrid/jobs.py` and `prompts/plausibility/v1.md` implement change 3.
- FR-006: the detector pipeline implements change 7 without an edit to `refusal.py`,
  `llm_judge.py`, `tool_classifier.py`, `strategies/` or `agent_scanner/scanner.py`.
- FR-007: `provenance.atoms` implements change 8.

## Clarifications

- Q: First or last listed verb? A: the first verb after the toolkit or MCP prefix (owner,
  2026-11-24, design change 1).
- Q: What does an empty override mean? A: the reply gave no role, so the verb rule types the
  tool. A non-empty override is never overruled.
- Q: Does a table tool take the verb rule? A: no. A tool the alias table maps keeps the V2 word
  rules on its table keyword.
- Q: Which wins where the audit and the design differ? A: the design (coordinator, 2026-11-24).

## Assumptions

- The scan's blast radius and trifecta legs keep the V2 word rules, through `keyword_roles`.
  Why: the design lists neither file under change 1, both are new on `develop`, and the verb
  rule would take the egress kind from verb-less names such as `http_request` there.
  Overturned if the owner wants one typing for chains and blast radius alike.
- A write verb gives every sink role it names: `transfer` is egress and high impact. Why: the
  design says "the sink role its verb names". The design's own count used egress and exec
  only; no chain flag or exfiltration class differs between the two readings.
- A blank id has no role. Why: it names no tool.
- An MCP id with no tool part (`mcp__server`) is typed on the whole id.

Rollback: revert the merge commit of this branch on `develop`.
