# Feature Specification: the fresh AgentDojo set and the provenance inputs in the harness

**Feature Branch**: `feat/065-harness-fresh`
**Created**: 2026-11-12
**Status**: Active
**Base**: `develop` @ f5ac085 (spec 063, the provenance detector, merged in #490)
**Input**: plan item G10-HARNESS-FRESH (ziran-paper goal G-10, tier smart). The binding text is
`prereg/patch-protocol.md` in taoq-ai/ziran-paper at `main` `d4befb1`: sections 5, 8, 10 and 11,
and the section 16 deviations. The fresh include rule is the one G10-REGISTER committed in
`prereg/g11-intake/agentdojo.json` (`rules.fresh`). The run notes add duties from the gates of
ziran-paper #122 and #127 and ziran #490; each is listed under "Duties" with where it is met.

## The item in my own words

ziran's patched side-effect detector (spec 063) judges a tool call by where its argument values
came from: the user's task, an earlier tool result, or the attack text. The external benchmark
harness feeds it AgentDojo logs but, before this item, passed only the prompt, the assistant text
and the calls. So the detector could not run its rules. This item makes the harness pass the four
inputs of protocol section 5, adds the fresh AgentDojo set, and reports two rows per trace: task
known (rule T3) and payload known (rule P1).

- (a) A new benchmark `agentdojo_fresh` admits a run log when its path is
  `runs/<model>/<suite>/<user_task>/<attack>/<injection_task>.json`, the model folder is
  undefended (not `Meta-SecAlign-70B`, no defence suffix) and the attack is `direct`,
  `ignore_previous`, `injecagent` or `tool_knowledge`. Other paths are counted as outside.
- (b) Every AgentDojo unit carries `trusted_task` (the first user message's text, the same as
  `prompt`), `tool_results` (`{message_index, text}` per tool message, in log order, whole:
  the content, then `error: <error>` for a failed call, as ziran-paper's
  `g11_judge_spike.render_trace` renders it), `message_index` on each call, and `payload`. The task-known variants (`whole`,
  `post_injection`, `text_only`) pass `payload: []`. The payload-known variants (`payload_whole`,
  `payload_post_injection`) pass the log's `injections` values in key order.
- (c) Both pins receive identical units. The worker passes exactly those three metadata keys
  and the calls as the harness built them, so nothing from the log beyond them reaches the
  detector.
- (d) The deterministic verdict is `provenance(...).hit` at a pin that ships the module, and is
  absent at study-v1. study-v1 ignores the added fields.
- (e) Rows hold ids, labels, cells and verdicts only. The isolation, sha256-before-parse,
  counts-only output and socket block of 50b472f are unchanged.

My words and the item agree. The item's acceptance 1 names whole-split counts. Those include the
lockbox, which this item must not open. So acceptance 1 runs on the iterate side, unit by unit,
against the committed G-9 rows (see "Acceptance as run").

## Duties from the run notes

| Duty | Where it is met |
| --- | --- |
| Pass `trusted_task`, `tool_results`, `message_index` and `payload` (empty on the task-known row) | `mapping.agentdojo_units`, `run._worker_unit`, `worker._score` |
| Check the keys at intake (exit 3) before scoring | `mapping.agentdojo_units`: a tool message with no open call of its id, a blank first user message, and `injections` that is not an object of strings each fail intake |
| Strip target-supplied copies | the worker builds `metadata` from the three harness keys only, and each call from `name`, `arguments` and `message_index` only; `HttpAgentAdapter.invoke` drops the three keys from a remote agent's metadata. The key names are one constant, `ziran.domain.interfaces.adapter.PROVENANCE_METADATA_KEYS`; the worker cannot import ziran outside the pin, so it holds a copy that a test keeps equal. The streaming path (`stream()`, `AttackExecutor._invoke_streaming`) is G10-HARDEN's: it strips the keys on every path |
| The deterministic row reads `provenance().hit`, never `pipeline.evaluate().successful` | `worker._score`, predictor `deterministic`; the primary of `agentdojo_fresh` |
| A label-blind rule for a detector raise | below, "A detector raise" |
| The row allowlist and its types | `run.check_row` |
| The dev replay on the iterate split, 0 differences | below, "Acceptance as run" |
| The commit-then-score check | not here: G11-SCORE's runbook runs `hybrid_send.py verify`; the worker gains no git call |
| Never open fresh, reserve or lockbox data | the replay fetched the iterate logs only, through `g11_dev_sets.guard` with `lockbox=False` |

## Intake checks of the keys (protocol section 10)

Each failure reports the benchmark as not evaluated (exit 3), before any worker starts. The
reason names the log path and message index, never an id or text.

1. A tool message must answer an open call: one of the calls of the latest assistant message
   whose id (`tool_call_id`, null included) no earlier tool message has answered. On the 9,912
   iterate logs, all 33,329 tool messages match.
2. The first user message, when there is one, must not be blank. A log with no user message (148
   iterate logs, each with an empty `messages` list) carries no `trusted_task` key, so the
   detector reads no task. That is the literal reading of section 5 (there is no first user
   item), and it keeps those units' study-v1 verdicts and the probe's (no call, no hit).
3. `injections` must be an object whose values are strings.

## A detector raise

`provenance()` raises `ProvenanceInputError` when a key is malformed or the trusted task holds
the payload. The intake checks above prevent the first. The second depends on the log.

Rule: a unit on which any pin raises `ProvenanceInputError` is excluded as `detector_raised` at
every pin. Its row keeps its label and the verdicts of pins that did not raise, and the summary
counts, per pin, the units its raises relabel under `detector_raised`. A unit already excluded
(an `error` log) keeps its reason and is not counted. The rule reads only the detector's input, never
the label, so it is label-blind, and it keeps the pins paired for McNemar. Any other exception
still stops the worker (exit 2, no summary). On the iterate side the count is 0 at both pins.

This rule is new in the protocol's terms, so it needs a dated deviation in ziran-paper before
the fresh run. The handoff gives the text.

## Rows (protocol section 8)

One row per unit, with exactly these keys: `benchmark`, `unit_id`, `variant`, `cluster`,
`cells`, `label`, `excluded`, `notes`, `verdicts`, `reply_outcome`. `check_row` refuses any
other key, any missing key, and any value outside these rules, before the rows file is written
(exit 2, nothing written). The message names the failing key, never a value.

| Key | Rule |
| --- | --- |
| `benchmark` | a benchmark of `collect.PRIMARY` |
| `variant` | one of the five variants above |
| `unit_id` | an id whose segments may also hold `:` (`member:line`, `row:3`) |
| `cluster` | an id (`[A-Za-z0-9_.-]` segments joined by `/`; a sha256 is one); the harness writes the sha256 of a cluster that holds record text (InjecAgent's instruction pair, a JailbreakBench goal) |
| `cells` | an object of id to id |
| `label` | a boolean or null |
| `excluded` | null, `error`, `parse_error`, `invalid`, `label_not_binary` or `detector_raised` |
| `notes` | a list from a closed vocabulary: `no_marker`, `shipped_eval_differs` and the 14 `invalid_reason` values the pinned InjecAgent evaluator sets |
| `verdicts` | an object of `<pin>/<predictor>` to a boolean; pin names match `[A-Za-z0-9_.-]+` (checked at `--pin`) |
| `reply_outcome` | null (the harness makes no model call) or one of the seven classes of section 4 |

So `prompt`, `content`, `tool_calls`, `trusted_task`, `tool_results` and `payload` never reach a
row. The G-9 row shape (one row per pin and unit, with `pin` and the predictors as keys) is
replaced for every benchmark: the G-9 rows are committed and this harness does not rewrite them.

## Acceptance as run

1. Given the G-9 split and the study-v1 pin, when the new mapping scores it, the verdicts equal
   the committed ones. Run on the iterate side only (9,912 logs, 9,847 analysed, 1,765
   positives, as `g11_dev_sets.json` `lockbox.all.iterate` records): the study-v1 refusal,
   side-effect and pipeline verdicts of all 29,736 task-known units equal the committed G-9 rows
   (`study/results/ext-eval/agentdojo.rows.jsonl.xz`), 0 different, 0 missing. The whole-split
   counts (1793/2598, 8585/11480, 1793/4688) include the 4,257 lockbox logs and are not re-run.
2. Given a hand-made log with a marker in a tool result and in an injection value, when the
   harness runs, the rows and summary hold ids, labels, cells and verdicts only, and the marker
   appears in no output (`test_a_planted_marker_reaches_no_output_and_both_rows_are_scored`).
3. Given a hand-made log whose tool message has no matching call, when intake runs, the
   benchmark is not evaluated with the reason, before any worker starts
   (`test_a_tool_message_with_no_matching_call_is_not_evaluated_before_any_detector_call`).
4. Dev replay (run note from #490): on the same 9,847 analysed iterate logs, the patched pin's
   `deterministic` verdict against the frozen probe's (`g10_dev_probe.py`) `t3` on `whole` and
   `p1` on `payload_whole`, with 0 raises. `dev_replay.py` in this folder computes it from the
   harness rows.
   - At `887745b` (tool results without the error text): 0 differences on T3 and on P1.
   - At `e053a39` (with the error text, fix round 1): P1 0 differences; T3 2 differences. Both
     are negatives the harness flags and the probe does not; their logs hold 13 and 4 failed
     calls. The probe reads tool content only. 1,510 analysed logs hold a failed call. So the
     T3 counts D29 and D30 do not reproduce under the error text, and the P1 counts D27 and D28
     do. Which reading governs is the owner's to register.

## Out of scope

Any detector, analyzer or threshold file; the label as an input; `placeholder_args`; the reserve
include rule; the commit-then-score check; any fresh, reserve or lockbox log.

## Assumptions

- The payload-known row is a variant (`payload_whole`, `payload_post_injection`), because the
  section 8 allowlist has no key for the row. Why: rows stay one unit each, and B1's "variant
  `whole`" of the payload-known row is `payload_whole`. Overturn: the registered deviation names
  another encoding.
- `text_only` has no payload variant: with no call, neither rule can fire, so it would repeat
  `text_only`. Overturn: a gate wants the row for symmetry.
- `post_injection` still cuts at `<INFORMATION>`. Three of the four fresh attacks do not use that
  marker, so their post-injection rows are empty and counted under `no_marker`. The variant is
  reported beside the bars, with no bar. Overturn: the protocol registers another cut for them.
- `reply_outcome` may be null, since the harness makes no model call. Overturn: G11-SCORE wants
  the key absent from harness rows.
- The HTTP adapter strip is in scope, because the #490 run note names the pass-through. Overturn:
  the planner moves it to its own item.
