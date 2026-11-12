# Feature Specification: prompt registry and record-and-replay model client

**Feature Branch**: `feat/064-llm-seam`
**Created**: 2026-11-12
**Status**: Draft
**Input**: plan item G11-LLM-SEAM (goal G-11); ziran-paper `prereg/patch-protocol.md` sections 2, 4, 5, 6 and 11.

## The item in my words

The hybrid detector needs model calls, but ziran has no API key and the frozen study harness
blocks sockets and processes. So ziran must never send a call. It renders each request, writes it
to a file, and later reads the stored reply back by key. ziran-paper's `hybrid_send.py` does the
sending in between, through its registered CLI client.

This item builds the seam only:

1. A prompt registry. Prompt files sit at `ziran/application/hybrid/prompts/<job>/v<N>.md`. A
   loader returns a prompt by job and version, with the sha256 of its bytes. A version that has
   merged is never edited, and a test checks that against the base branch.
2. A request key: the sha256 over the prompt file's bytes, the model id, the client version
   string and the rendered text. Change one of the four and the key changes; keep all four and it
   stays the same on every run.
3. `RecordReplayClient`, a `BaseLLMClient` in `ziran/infrastructure/llm/replay_client.py`. In
   record mode, `complete()` appends `{"key", "job", "unit", "text"}` to a request file the caller
   names, opens no socket, and returns a typed pending result. In replay mode it returns the
   stored reply for the key, or pending when there is none.
4. The `hybrid_route_share` setting (protocol section 6): the share of band units sent to the
   model, `0.0` by default (deterministic mode, no call). Band units are taken in ascending
   sha256-of-unit-id order.
5. A pending or unparsable result never changes a verdict. The unit keeps its deterministic
   verdict and is counted in `llm_pending` with its cause. Only band units are ever sent, and a
   usable reply is combined with the first-pass verdict by the job's merge rule, so a reply
   cannot remove a first-pass decision the protocol keeps (section 2: a provenance hit stays an
   attempt).
6. The request file holds benchmark or user text. It is written only to the named path and never
   logged.

No detector, analyzer or threshold changes, and no network client is added. With no client
configured, every benchmark and the detection dataset give develop's results.

## User Scenarios and Testing

### User story 1: a stable request key (P1)

**Acceptance**: Given a prompt file and a rendered input, when the key is computed, then changing
one byte of the prompt, the model id, the client version or the input changes the key, and the
same four give the same key on every run.

### User story 2: record without a socket (P1)

**Acceptance**: Given record mode with sockets blocked by the test, when a job calls `complete()`,
then one request line is written to the named path, no socket is opened, and the caller receives
pending.

### User story 3: replay with a missing key (P1)

**Acceptance**: Given replay mode with one stored reply and one missing key, when two units are
scored, then the first uses the reply, and the second keeps its deterministic verdict and is
counted as `llm_pending`.

### User story 4: deterministic mode unchanged (P1)

**Acceptance**: Given no client configured, when the detection dataset and the benchmarks run,
then every result equals develop's.

### Edge cases

- `hybrid_route_share` outside 0.0 to 1.0, or above 0.0 with no client: refused with `ValueError`.
- A duplicate unit id among band units: refused.
- A job or version that is not a plain name or a non-negative integer: refused, so no path escapes
  the prompt folder.
- A request with more than one message, or a role other than `user`: refused, since the sender
  sends the text as the one user message.
- A blank text or a unit id the sender would refuse: refused at record time.
- The same key recorded twice: written once.
- A replies file with a malformed line, an outcome outside the sender's seven classes, or a
  repeated key: refused, naming the line, never its text.
- A symlink at the request path or at any parent folder, dangling or not: refused before any
  read or write; the file is opened with `O_NOFOLLOW` and created owner-only.
- A unit outside the band: never sent, its first-pass verdict passed through.
- A band unit with no first-pass verdict: refused.
- A stored outcome other than `reply` (`unparsed`, `no_text`, `not_sent_oversize`,
  `step_stopped`, `no_reply_at_bound`, `scan_hit`): pending, with the outcome as the reason.

## Requirements

- **FR-001**: `load(job, version)` returns the prompt's job, version, text and sha256.
- **FR-002**: `request_key(prompt, model, client_version, text)` hashes the four parts with a
  length prefix each, so no two different tuples share a byte string.
- **FR-003**: A test fails when a prompt file present on the base branch differs at the head or is
  gone.
- **FR-004**: Record mode writes only to a path ending in `.requests.jsonl`, makes no network or
  process call, and returns `PendingResponse(reason="recorded")`.
- **FR-005**: Replay mode reads ziran-paper's `outcomes.jsonl` rows `{"key", "unit", "job",
  "outcome", "fields"}`. A `reply` row returns its fields as JSON content; any other row or a
  missing key returns `PendingResponse`.
- **FR-006**: `decide()` routes the first `hybrid_route_share` of the band units only, asks the
  client, and sets a usable reply's unit to `merge(first_pass, reply)`, the job's rule. Every unit
  with a pending or unparsable reply keeps its first-pass verdict and is listed in `llm_pending`,
  a mapping from unit to cause: the pending reason (`recorded`, `missing` or the sender's outcome
  class) or `unusable_reply`.
- **FR-007**: Neither the client nor `decide()` logs a request or reply text.
- **FR-008**: No existing module imports the new ones, so no shipped path changes.

## Out of scope

Any CLI client; sending; the trace judge, capability and plausibility prompts and their
rendering; thresholds; `benchmarks/replay_llm_client.py`, left as it is.

## Assumptions

- **Evidence values for prompt v1 (open design point).** Prompt v1 renders evidence values, but
  #490's `CallEvidence` holds argument paths only, and for an argument over 60 characters one path
  covers several values. Choice: the trace judge's renderer re-runs provenance's own matching
  (`atoms`, `found` and `norm` in `ziran/application/detectors/provenance.py`) on the call's
  arguments to recover the values per path. #490 gains no field. Why: #490 is in its final gates,
  and the matching functions are already public there, so the values come from the same code that
  chose the paths. What would overturn it: the renderer needing a value the matching cannot
  recover from the arguments, or #490 changing those functions' names. This item ships no
  renderer, so it imports nothing from #490.
- **Placeholder prompts live under `tests/fixtures/hybrid_prompts/`, not in the package.** The
  protocol (section 4) has v0 and v1 of each job ship byte-equal to the spike files, and a merged
  version is never edited. A placeholder shipped at `prompts/<job>/v0.md` would block that. The
  loader takes the folder as an argument, so tests load the fixtures. What would overturn it: a
  ruling that the job items use other version numbers.
- **Routing rounds down.** At share `s` and `n` band units, `floor(s * n)` units go to the model,
  so a setting never sends more than its share. The protocol does not say; it reads every setting
  from the replies stored at `1.0`, where the rule does not matter.
- **The repeat index is not in the key yet.** Protocol section 4 sends 200 units a second time
  under a repeat index. Adding it later as an optional part that is absent at repeat 0 leaves
  every key built here unchanged.
- **The base-branch check compares against the run's own base.** On a pull request the test
  workflow fetches `github.base_ref` at depth 1; on a push it fetches the commit the push moved
  past (`github.event.before`), or compares the commit with itself for a new branch. The test
  reads the base from `ZIRAN_PROMPT_BASE`. In CI an unfetched base fails the test; locally it
  skips.
- **The key encoding is a third form.** `request_key` is length-framed over the prompt text,
  model id, client version and rendered text. ziran-paper's `chainset.py` and
  `g11_judge_spike.py` key JSON over the prompt sha256, model, CLI version and more (effort,
  repeat). Same inputs give different keys, so a request keyed two ways could be sent twice and a
  ziran replay cannot read chainset-keyed outcomes. The planner adds G11-PROTOCOL-DEV2 to register
  one formula before the freeze addendum; this item makes no key change until then. What would
  overturn it: that item registering another formula, which this function then adopts.
- **The merge rule belongs to the job.** `decide()` takes `merge` as a required argument: each job
  item supplies its rule (for the trace judge, a provenance hit stays an attempt). The seam keeps
  no default, so no job can drop a first-pass decision by leaving it out.
- **`PendingResponse` sits in `ziran/infrastructure/llm/base.py`, beside `LLMResponse`.** The
  application layer imports it at runtime from the port module, not from the adapter.
