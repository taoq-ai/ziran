# Feature Specification: the harness's hybrid row and routing-share rows

**Feature Branch**: `g11-hybrid-harness`
**Created**: 2026-11-12
**Status**: Draft
**Input**: plan item G11-HYBRID-HARNESS (goal G-11), split from G11-HYBRID-JOBS (ziran#494);
ziran-paper `prereg/patch-protocol.md` sections 4, 6 (routing share) and 8, and its deviation of
2026-11-12 (the harness rows).

## The item in my words

The external-eval harness of spec 065 scores the deterministic rows. Spec 067 shipped the trace
judge on the record-and-replay seam. This item joins the two:

1. `run.py` takes `--hybrid-replies <outcomes.jsonl>` or `--hybrid-record <x.requests.jsonl>`,
   with `--hybrid-model` and `--hybrid-client-version`. The worker builds the
   `RecordReplayClient` of the pin and runs `judge_traces(..., share=1.0)` on each AgentDojo
   variant, task-known (`whole`, `post_injection`, `text_only`) and payload-known
   (`payload_whole`, `payload_post_injection`), one judge call a variant. Protocol section 2
   sends task-known band traces to the judge, and section 6 reports the task-known row beside
   every row.
2. Each judged unit gets `hybrid` (the judge's verdict at 1.0) and `hybrid_r025`, `hybrid_r050`
   and `hybrid_r075`: the same stored replies for the units `routed(band, s)` sends at that
   share, the first pass for the rest. No other model call is made for them.
3. The four names join `PREDICTORS`, so `check_row` admits them. A row's `reply_outcome` holds
   the sender's outcome class of its judge request, and the new row key `no_reply_cause` holds
   `missing` or `unusable_reply`, the two ziran-side causes outside those classes.
4. The worker passes the judge's keys (`user_messages`, `final_answer`, a call's `id`, a result's
   `tool_call_id` and `name`), so a harness render equals the spike's on multi-user and
   out-of-order logs.
5. A record run writes the request file and scores nothing. Each pin's summary counts, per
   variant, the band, the units each share sends, the outcomes, the no-usable-reply units by
   cause and true label, and the renders the mask changes: counts only.

**Acceptance.** Given stored replies for a synthetic fresh set, when the harness runs, then the
hybrid and routing rows are written and pass `check_row`, with no model call.

## How this fails

1. A harness render differs from the spike's, so the fresh judge reads requests it was never
   chosen on. Guarded by a byte-for-byte test of every spike case through mapping, `run` and the
   worker's metadata.
2. A routing row is computed with another order or rounding than `routed`. Guarded by building
   the rows with the pin's own `routed` and a test against it at 1 of 5, 2 of 5 and 3 of 5.
3. A missing or blocked reply reads as a negative. Guarded by keeping the first pass and counting
   the cause per variant (`missing`, `no_text`).

## Requirements

- **FR-001**: The worker's `METADATA_KEYS` are the detector's three keys and the judge's two
  (`JUDGE_METADATA_KEYS`). No detector reads the judge's keys, at the head or at `study-v1`.
- **FR-002**: An AgentDojo call carries its `id`; a tool result its `tool_call_id` and the
  `name` of its `tool_call`; a unit its `user_messages` and `final_answer`, as
  `tests/fixtures/hybrid/spike_render.py` reads the log.
- **FR-003**: Each request is keyed by `request_key` at repeat 0, the four-part key.
- **FR-004**: `hybrid_rXXX` is `hybrid` for a unit in `routed(band, s)`, else the provenance hit.
- **FR-005**: An excluded (`error`) unit is not sent; a unit the pin's detector raises on is not
  sent at that pin; a judged unit outside the band keeps its first pass and has no outcome.
- **FR-005a**: The record path reaches the client unresolved, so a planted link at the file or
  its folder is refused (CWE-59). A missing replies file and an empty model or version exit 2.
- **FR-005b**: An old pin without the hybrid package runs beside a new one; `reply_outcome` and
  `no_reply_cause` come from the first pin that sent the unit.
- **FR-006**: A hybrid flag set that is not whole (a path with no model or version, both paths,
  a record name not ending in `.requests.jsonl`) and a run where no pin ships the jobs exit 2.
- **FR-007**: `_assert_linear` times with `time.process_time`, best of three, failing early when
  the best of two large runs is 12 times the small one or more.

## Out of scope

The 200-unit repeat send (protocol section 4) and the capability and plausibility jobs in the
harness. Reading any fresh, reserve or lockbox log.

## Assumptions

- **The routing rows are built in the worker.** `run.py` may not load ziran (it refuses to), so
  the pin's `routed` runs in the worker on the band of the 1.0 run. `run.py` adds the rows to the
  allowlist and writes them. Overturn: the planner wants `run.py` to recompute them from rows.
- **The three names `hybrid_r025`, `hybrid_r050`, `hybrid_r075` are new.** ziran-paper#128
  registered `hybrid`; the owner approved the three in this item's promise. G11-FREEZE-ADDENDUM
  registers them by dated deviation before any fresh or reserve run.
- **`reply_outcome`** is the first pin's outcome class that sent the unit. A reply ziran's parse
  refuses is still the sender's `reply`; `missing` is no class, so null, and counted.
- **The judge's keys are added to the detector's metadata too**, as the gates asked. Overturn: a
  detector at a registered pin reads them.
- **Registered sentences this departs from**, each for G11-FREEZE-ADDENDUM to register by dated
  deviation: protocol section 5 line 136 ("A key with another name or shape is a deviation":
  the worker passes `user_messages` and `final_answer`, calls carry `id`); #128 line 870 (a
  tool result is `{message_index, text, error?}`: it gains `tool_call_id` and `name`); line 880
  (the ten row keys: `no_reply_cause` is an eleventh); line 890 (the predictor names: three
  routing names). The summary's `pins.<pin>.hybrid` shape is new too.
- **The mask count is the record run's output.** The operator's one command on real logs is the
  record run (`--hybrid-record`), which prints the per-variant counts.
