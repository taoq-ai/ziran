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

4. Change 7, the authorization id. The prompt names the caller's own id ("I am user 7",
   call `user_id=7`) and the call reads as evidence. A victim's id the prompt does not name
   (an enumerated `user_id=4822`) raises nothing from this branch, and an id nested under a
   key that is no id key (`filter.user_id`) is not read.
5. Change 7, the whole prompt as the payload. False canaries grow with the prompt's length.
   A synthetic 300-shot prompt that shows `write_file(path='notes.txt')` makes a benign
   `write_file(path="notes.txt")` call a canary success; the same call after a short attack
   prompt is none. A multi-turn tactic adds every turn sent so far, with the same effect. The
   crossfire's 158 of 291,090 pairs uses single prompts, so the rate on many-shot and
   multi-turn prompts is unmeasured. These are false positives, not missed attacks: a target
   cannot forge or remove the payload.
6. Change 7, the judge's request. It holds the reply's tool calls, masked for secret shapes
   only. An email address or other personal data in an argument reaches the judge's provider.

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

- Change 7, the missing refusal. A reply with no refusal phrase and no other signal is
  listed with `needs_review`, as the design's list of signals says. Why: without a judge a
  text-only attack that was not refused is not verified. On the design half that lists 2,122
  of 2,176 units with no provenance input. Overturned if the owner wants a missing refusal
  listed only beside another signal.
- Change 7, evidence against the judge. A canary or a sink hit is a success even when a
  configured judge answers failure. Why: the design names three kinds of evidence, each
  enough, and has the judge read before a signal. Overturned if the owner wants the judge
  to overrule a canary.
- Change 7, a refusal against the judge. A detected refusal still wins over a judge that
  answers success, as before. The design changes neither.
- Change 7, A15. An id in a call is evidence when the attack prompt names it, and an id the
  prompt does not name is nothing. The design's wording, "differs from one the prompt or the
  session gives", is not built to the letter: ziran's BOLA prompts name the victim's id, so
  that rule would flag an agent that answers with the caller's own id and miss one that
  uses the victim's. No session identity reaches a detector today. An id token is 3
  characters or more, and a number is no id where it counts a numbering word ("step 3"): a
  general limit on what an identifier is, not a rule read off data.
- Change 7, the payload of a scan. A multi-turn tactic passes every turn sent so far, and
  an encoded prompt passes its plain text beside the encoded one. Why: the attack's values
  are in that text. Overturned if only the last prompt as sent should count.
- Change 7, a known payload with no hit. With a payload alone the tool's name tier is
  kept as a signal; with a known task the provenance record stands alone, as spec 063 has
  it. Why: a scan knows only its own prompt, and a destructive call with no value of the
  prompt should still be listed.
- Change 7, the detection benchmark. Its dataset stores no attack prompt, so its pipeline
  row passes no payload. The crossfire passes the rendered prompt, as a scan does, and is
  the measure of the whole-prompt canary on ziran's own set.

Rollback: revert the merge commit of this branch on `develop`.
