# Proposal: should ziran ship hybrid mode as the default?

Status: Draft. This note changes no code and no default.

Labels: **EXISTING** is behaviour on `develop` at commit `c718a79`, cited by file and line.
**PROPOSED** is a change this note suggests and nobody has built.

## Recommendation

Keep `hybrid_route_share` at `0.0` by default. Turning the hybrid on today would not remove the
false positive that motivates the question, so it would add cost and a key dependency for no
gain. Fix that false positive in the deterministic first pass instead. Revisit the hybrid default
only once the benchmark run in [Measurement](#measurement-that-settles-it) shows it lowers FPR
without losing recall.

## The problem

A scan of a real model reported attacks as successful when the agent had only read a file and
replied normally. The detection benchmark shows the same thing on labelled data:

- EXISTING: on the `sensitive_tool_output` slice the pipeline scores 12 TP, 28 FP, 2 FN, 8 TN,
  an FPR of 0.78 (`benchmarks/results/detection_accuracy_baseline.json`,
  `per_category_confusion.sensitive_tool_output.pipeline`; `docs/reference/benchmarks/detection-accuracy.md:168`).
- EXISTING: of the 14,447 crossfire pairs flagged, 14,029 come from that slice
  (`benchmarks/results/detection_accuracy_baseline.json`, `crossfire.flagged_by_category`). The
  benign `read_file`, `get_secret` or `read_config` call trips the side-effect name tiers for
  every prompt (`docs/reference/benchmarks/detection-accuracy.md:190`).
- EXISTING: whole-set pipeline FPR is 0.20 at recall 0.86 on 447 examples
  (`benchmarks/results/detection_accuracy_baseline.json`, `pipeline`).

The mechanism:

1. EXISTING: `read_file` is a HIGH tool pattern (`ziran/domain/tool_classifier.py:164`, inside
   `HIGH_PATTERNS` from line 109).
2. EXISTING: a HIGH call scores 1.0 at confidence 0.90 (`ziran/application/detectors/side_effect.py:121`).
3. EXISTING: the resolver returns success when side-effect scores at least `hit` (0.7) at
   confidence at least 0.7 (`ziran/application/detectors/pipeline.py:464`;
   `ziran/application/detectors/thresholds.py:50`, `:74`). That branch runs before the LLM
   judge branch (`ziran/application/detectors/pipeline.py:520`), so even a configured judge never
   sees these cases.

## What the hybrid does today

- EXISTING: `hybrid_route_share` defaults to `0.0`, deterministic mode with no model call
  (`ziran/application/detectors/thresholds.py:110`).
- EXISTING: `ziran scan --hybrid-route-share` overrides it (`ziran/interfaces/cli/main.py:354`).
  A share above `0.0` exits with a usage error, because scan has no client for the hybrid
  (`ziran/interfaces/cli/main.py:411`, `:1889`, `:1967`). A config value above `0.0` with no
  LLM backbone is ignored with a warning (`ziran/interfaces/cli/main.py:640`).
- EXISTING: the trace judge sends only band traces, those whose provenance state is `evidence`
  (`ziran/application/hybrid/jobs.py:241`). Provenance is `not_applicable` unless the response
  carries `trusted_task` or `payload` (`ziran/application/detectors/provenance.py:316`).
- EXISTING: scan never sets those keys, and the HTTP adapter strips them from a target's
  metadata (`ziran/infrastructure/adapters/http_adapter.py:200`;
  `ziran/domain/interfaces/adapter.py:24`).
- EXISTING: no `sensitive_tool_output` item carries `trusted_task` or `payload` (all 50 items
  under `benchmarks/ground_truth/detection/sensitive_tool_output/`).
- EXISTING: the only caller of `judge_traces` outside the hybrid package is the external-eval
  worker (`benchmarks/external_eval/worker.py:148`).

So the band is empty for every scan and for the slice that holds the false positives. A share of
1.0 would send nothing and change no verdict there. The hybrid helps only where a caller supplies
the task or payload, as the external-eval harness does.

## Cost and latency

- EXISTING: the trace judge prompt v1 is 3,115 bytes (`ziran/application/hybrid/prompts/trace_judge/v1.md`).
  That is about 780 tokens at the repository's 4 characters a token
  (`ziran/application/attacks/many_shot.py:21`, `:39`).
- EXISTING: the rendering cuts each tool result at 4,000 characters, about 1,000 tokens
  (`ziran/application/hybrid/jobs.py:53`). One request goes out per routed unit.
- EXISTING: the library holds 677 vectors and 930 prompts
  (`benchmarks/results/detection_accuracy_baseline.json`, `crossfire`).
- Estimate, not measured: if every response of a full-library scan were in the band, share 1.0
  would send about 930 requests of roughly 1,800 input tokens each, about 1.7M input tokens a
  scan. Share 0.25 sends a quarter of that, since `routed` takes `floor(share * n)` band units
  (`ziran/application/hybrid/__init__.py:70`).
- EXISTING: dollar cost is unpriced out of the box. The shipped price table lists no models
  (`ziran/infrastructure/llm/prices.yaml:8`), so the spec 047 ledger reports tokens and leaves
  cost unknown until an operator adds `.ziran/prices.yaml` (`specs/047-token-budget-cost-cap/spec.md:98`).
  `--max-campaign-tokens` and `--max-cost` already cap a run (`ziran/interfaces/cli/main.py:309`, `:317`).
- EXISTING: `decide` awaits each routed unit in turn (`ziran/application/hybrid/__init__.py:115`).
  Added latency is the sum of the call latencies, which nobody has measured.
- EXISTING: the spec 043 prefilter benchmark ran with no live cheap model (`cheap_model: null`
  in `benchmarks/results/two_tier_judging.json`). Its 0.47 frontier-call reduction is
  replay-only, so no live latency or cost number exists for any model stage.

## Offline and keyless use

- EXISTING: a scan with no `--llm-provider` or `--llm-model` builds no LLM client
  (`ziran/interfaces/cli/main.py:594`) and runs every detector offline.
- EXISTING: `decide` raises when the share is above `0.0` and no client is given
  (`ziran/application/hybrid/__init__.py:111`).
- A default above `0.0` would therefore break every keyless scan, or need a silent fallback to
  `0.0`. Either way the default the user gets with no key stays deterministic.
- PROPOSED: if the hybrid ever defaults on, it applies only when an LLM backbone is configured,
  and the scan summary prints the effective share. A keyless scan keeps `0.0` with no warning.

## CI use

- EXISTING: the composite action runs `ziran scan` with no LLM flags (`action.yml:189` to `:203`),
  so CI scans are keyless today. Forked pull requests cannot read repository secrets, so a
  key-dependent default would give fork and branch runs different verdicts.
- EXISTING: `RecordReplayClient` returns a stored reply by request key, or a pending result
  (`ziran/infrastructure/llm/replay_client.py:62`, `:134` to `:139`). The key covers the prompt
  file, model id, client version and rendered text (`ziran/infrastructure/llm/replay_client.py:43`).
- So a committed reply file replays only for fixed traces such as benchmark fixtures. A live
  agent's reply text changes the rendered text, so the key misses, the unit is pending, and it
  keeps its deterministic verdict. Replay suits benchmark CI, not scans of a changing agent.

## Determinism and replay

- EXISTING: band order is sha256 of the unit id, so the routed set is the same on every run
  (`ziran/application/hybrid/__init__.py:70`). Prompt files are pinned by sha256
  (`ziran/application/hybrid/prompts.py:46`).
- EXISTING: a pending or unusable reply keeps the first-pass verdict and is counted in
  `llm_pending` (`ziran/application/hybrid/__init__.py:115` onward). A provenance hit stays an
  attempt whatever the judge replies (`ziran/application/hybrid/jobs.py:226`).
- A live model is not deterministic. With the hybrid on by default, two runs of the same scan
  could differ on band units. Deterministic mode, and replay from a fixed reply file, do not.

## Measurement that settles it

PROPOSED, in two steps.

1. Widen the benchmark input. Give the `sensitive_tool_output` and the other tool-call items a
   `trusted_task` (the benign task the agent was doing), so the provenance band is not empty by
   construction. Without this step the run below reports no change at any share, which is itself
   the answer for the current band.
2. Add a hybrid predictor to the detection benchmark (`benchmarks/detection_accuracy.py`, spec 021) and run it
   at route shares 0, 0.25, 0.5 and 1.0, from one recorded reply file. The
   external-eval harness already scores these shares from stored replies
   (`benchmarks/external_eval/run.py:62`, `:121`). For each share, report:
   - pipeline FPR and recall on the whole set and on `sensitive_tool_output`;
   - units sent, `llm_pending` by cause, and input tokens from the usage ledger;
   - wall time of the live record run.

Decision rule, PROPOSED: make the hybrid the default when an LLM backbone is configured only if
some share cuts `sensitive_tool_output` FPR below 0.25 and keeps whole-set recall within the
baseline tolerance of 0.02 (`benchmarks/results/detection_accuracy_baseline.json`, `tolerance`).
The keyless default stays `0.0` in every outcome.

## Cheaper fix to try first

PROPOSED, a separate item: in the deterministic path, score a read-only tool call that returns
benign content as ambiguous, not a hit, so the resolver falls through to the indicator and judge
branches. This targets the 28 false positives directly. It costs no tokens and keeps scans
keyless and reproducible. The same benchmark slice measures it.

## Open questions

- Whether the hybrid should widen its band beyond provenance `evidence` to cover side-effect-only
  hits. That is a change to `ziran/application/hybrid/`, which this note does not propose to edit.
- Live per-call latency and price for any judge model: unmeasured.
