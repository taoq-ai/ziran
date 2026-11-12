# Feature Specification: the hybrid's three model jobs on the seam

**Feature Branch**: `feat/067-hybrid-jobs`
**Created**: 2026-11-12
**Status**: Draft
**Input**: plan item G11-HYBRID-JOBS (goal G-11); ziran-paper `prereg/patch-protocol.md` sections
2, 4, 5, 6, 8 and 16; ADRs 0007 (capability names-only) and 0008 (trace judge v1); the owner's
answer of 2026-11-12, "Opt-in, off by default (Recommended)", for typed chains.

## The item in my words

The seam of spec 064 can send a band unit to a model job and read the reply back. No job exists
yet. This item ships the three jobs of protocol section 2 on that seam:

1. **Prompts.** `ziran/application/hybrid/prompts/<job>/v<N>.md` holds the trace judge's v0 and
   v1 and the capability classifier's v0 and v1, byte-equal to the spike files the protocol
   registers, and a first plausibility prompt. A test pins each file's sha256.
2. **Trace judge.** A renderer turns one band trace (an `AgentResponse` with the section 5 keys)
   into the request the spike sent: task, calls with their arguments and an evidence line,
   results cut at 4,000 characters, final answer, payload. The evidence line names values, but
   `CallEvidence` keeps paths only (CWE-532). So the values come from one extraction function
   factored out of `provenance.py`, the same one T3 and P1 count with. A differential test holds
   the refactored `_evidence` to develop's on random calls.
3. **Parsers** accept only the registered reply forms. A capability reply whose tool count or
   `tool` numbers are wrong is pending as `reply_tool_count_differs` or `reply_index_mismatch`.
4. **Capability job.** Tools ziran's alias table does not map are sent, names only, at most 12 a
   request. A usable reply gives role overrides for typed chains.
5. **Plausibility job.** One agent and at most 12 typed pairs; only `yes` is a finding.
6. **Merge.** No reply removes a first-pass decision: a provenance hit stays an attempt, a unit
   outside the band is never sent, and a pending reply keeps the first pass, counted by cause in
   `llm_pending`.
7. **Repeat index** as an optional fifth key part. A key without it equals today's four-part key
   (ziran-paper#128's worked example).
8. **Settings.** `hybrid_route_share` (config and `ziran scan --hybrid-route-share`), default
   0.0. Beside it `typed_chains` (config and `ziran audit --typed-chains`), default off.
   `claude_code_audit.agent_chains` gains `typed` and `role_overrides`.

No live model call anywhere. Deterministic mode is unchanged.

**Acceptance 1.** Given recorded replies, when the hybrid runs, then a provenance hit stays an
attempt whatever the judge replies, and a pending reply keeps the first-pass verdict and is
counted by cause.

**Acceptance 2.** Given the registered spike prompt files, when the registry loads v0 and v1,
then their bytes and sha256 equal the spike files'.

## How this fails

1. The ziran rendering drifts from the spike's, so the judge reads a request it was never
   screened on. Guarded by a byte-for-byte test against the spike's own `render_trace`.
2. The refactor of `provenance.py` moves a T3 or P1 verdict. Guarded by the differential test and
   the probe parity tests of spec 063.
3. A crafted tool name or reply clears a table-typed role or a table chain (OWASP LLM01). Guarded
   by never sending a table tool and by a test that clears every role and keeps the table chains.

## Requirements

- **FR-001**: `load(job, v)` gives the five shipped files; their sha256 are pinned in a test.
- **FR-002**: `render_trace` equals the spike rendering of the same log; untrusted text is `| `
  lines, and no spelling of the markers survives.
- **FR-002a**: A `tool_results` item may carry `error` (ziran#493: `{message_index, text,
  error?}`, `error` only for a failed call). The renderer puts `error: <error>` after the
  content, as the spike did; the detector reads `text` only.
- **FR-003**: `evidence_values(response)` and `_evidence` read one function, `_kinds`.
- **FR-004**: `parse_trace`, the capability parse and the plausibility parse accept only
  `hybrid_send.py`'s forms; anything else is `unusable_reply`, or the capability causes above.
- **FR-005**: `decide(parse=...)` passes the unit id to the parse, and a parse may raise
  `UnusableReplyError(cause)` to name the pending cause.
- **FR-006**: `request_key(..., repeat=0)` is the four-part key; `repeat >= 1` adds
  `str(repeat)` as a fifth length-framed part. `RecordReplayClient.complete(repeat=...)`.
- **FR-007**: `DetectorThresholds.hybrid_route_share` in [0, 1], default 0.0, and
  `typed_chains`, default False.
- **FR-008**: No module under `ziran/` outside `application/hybrid` imports the seam, so no
  shipped path can send (spec 064's guard still holds).

## Out of scope

The external-eval harness's `hybrid` predictor row and the routing rows at 0.25, 0.5 and 0.75:
they build on #493's worker, which has not merged, and they would take this item past about 600
lines of code. They split to their own item (see the PR). Wiring a record-and-replay client into
`ziran scan` or `ziran audit`.

## Assumptions

- **"A reply cannot clear a first-pass hit", on the static path.** The first pass decides a tool
  ziran's tables know and every table chain. Such a tool is never sent, so no reply can retype
  it, and role overrides reach only typed chains (#492), so no reply removes a table chain. A
  tool the name rules typed is band: a usable reply replaces its roles, and `unknown` on every
  role gives no role, as ziran-paper#128 registers and the capability spike scored. Overturn: the
  planner reads the rule as "a reply cannot remove a name-rule role either"; the merge then takes
  the union, at unmeasured dev counts.
- **Known to ziran's tables** means `canonical_tool_name(t) != t`, #492's `table` origin.
- **A tool result answers the earliest open call before it.** #493's `tool_results` hold no call
  id, and AgentDojo answers calls in order. The spike matched by id. Overturn: a log whose tool
  messages answer out of order; the result then needs its call index.
- **Plausibility v0 is new wording.** No spike exists, and the design's appendix C leaves the
  wording to the builders. It renders the agent's name, description, tools and instructions with
  SA001 secrets masked, each tool's roles and the pairs, exfiltration pairs first. Permission and
  hook files are not on a `ClaudeCodeAgent`, so they are not rendered. Overturn: the freeze
  addendum registers other inputs; that is a v1.
- **`ziran scan --hybrid-route-share` above 0.0 is refused**, by the seam's own rule: ziran scan
  has no model client for the hybrid. The config value is read where scan reads
  `.ziran/detectors.yaml` today, with an LLM backbone (spec 041). Overturn: an item wires the
  record-and-replay client into scan.
- **Typed chains and a baseline are refused together.** A baseline records untyped chains only.
- **The capability and plausibility jobs take no prompt version.** They run the registered one
  (v1 and v0); a v0 capability reply has no `tool` index and would be refused.
