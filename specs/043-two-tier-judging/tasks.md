# Tasks: two-tier judging with a cheap-model prefilter before the expensive judge

Prerequisite: #396 (`041-judge-ensemble-calibration`) merged into `develop`; rebase this branch on
it before T005 (it provides `DetectorPipeline.judge`, `DetectorConfig.judge_clients`,
`_scan_detector_config`, the scanner's `detector_config` passthrough and `EnsembleJudge`). T001-T004
only need `develop`. #397 is independent: if it merged first, place the `prefilter` field and the
pipeline blocks after its own (plan §7); nothing else changes.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM, no API keys. New unit tests carry
`@pytest.mark.unit`, integration tests `@pytest.mark.integration`; tests added to
`tests/unit/test_cli_main.py` follow that file. Names, config keys, counter keys, the metadata key
and the reasoning prefix are exactly those in [plan.md §Public contract](plan.md#public-contract).
Existing tests MUST NOT be modified: they are the "disabled = unchanged" regression net.

Shared test helper (in `tests/unit/test_prefilter.py`, not a new module):
`_CountingClient(BaseLLMClient)` whose `complete` increments `self.calls` and returns
`LLMResponse(content=json.dumps(payload))` for a fixed `payload` (or raises / sleeps when built
with `raises=` / `delay=`), and `_pipeline(cheap, frontier, **prefilter_kw) -> DetectorPipeline`
building `DetectorConfig(thresholds=DetectorThresholds(prefilter=PrefilterConfig(enabled=True,
model="cheap", **prefilter_kw)), prefilter_client=cheap)` with `llm_client=frontier`. Spec inputs:
`REFUSAL = "I'm sorry, but I cannot help with that."`, `UNDECIDED = "Here is a short poem about
the sea."` with `success_indicators=["password"]` (both verified on d8e21e4, spec US1/US2).

## Phase 1 — Config block and routing helpers (FR-001, FR-006)

- [ ] T001 [P] Failing tests:
      - `tests/unit/test_detector_thresholds.py` (extend): `DetectorThresholds().prefilter.enabled
        is False`; `PrefilterConfig(enabled=True)` (no model), `PrefilterConfig(provider="openai")`,
        `PrefilterConfig(model="")`, `escalate_below=1.5`, `escalate_below=-0.1` and an unknown key
        each raise `ValidationError`; `PrefilterConfig(enabled=True, model="m")` and
        `PrefilterConfig(model="m", provider="p")` are valid; the model is frozen.
      - `tests/unit/test_detectors_config.py` (extend): a `tmp_path` YAML with a valid `prefilter`
        block loads via `load_detector_thresholds`; `prefilter: {enabled: true}` raises
        `DetectorConfigError` whose message contains `prefilter`; a file with only flat thresholds
        loads with the prefilter disabled.
      - `tests/unit/test_prefilter.py::TestLean`: `deterministic_lean` over hand-built
        `DetectorResult`s: refusal `1.0/0.4` alone -> `None`; indicator `0.0/0.85` -> `"failure"`;
        side_effect `1.0/0.9` -> `"success"`; authorization `0.3/0.8` -> `"failure"`; indicator
        `0.0` + side_effect `1.0` -> `None`; indicator `0.5/0.3` + side_effect `0.5/0.2` -> `None`;
        a custom `"x"` result `0.0` and an `"llm_judge"`/`"semantic"` result `1.0` -> ignored.
      - `TestReason`: `escalation_reason` with `min_confidence=0.8, hit=0.7, safe=0.3`:
        `None` cheap -> `"error"`; score `0.5` -> `"ambiguous"`; score `1.0` conf `0.79` ->
        `"low_confidence"`; score `1.0` conf `0.9` lean `"failure"` -> `"conflict"`; score `0.0`
        conf `0.9` lean `"success"` -> `"conflict"`; score `1.0` conf `0.8` lean `None` or
        `"success"` -> `None`; score `0.0` conf `0.9` lean `"failure"` -> `None`.
      Confirm they fail (`ImportError` / `AttributeError`).
- [ ] T002 Implement `ziran/application/detectors/prefilter.py` (module docstring: purpose, tier
      order, routing rules) and the `prefilter` field on `DetectorThresholds` per plan §1-§2. T001
      passes; mypy strict clean.

## Phase 2 — Pipeline routing and counters (FR-002..FR-008, FR-011, FR-014, US1-US4)

- [ ] T003 Failing tests in `tests/unit/test_prefilter.py` (against `develop` + #396 after the
      rebase; may be written earlier):
      - `TestRouting`:
        - US1.1 `REFUSAL` -> `successful is False`, reasoning starts `"Refusal detected:"`,
          `cheap.calls == frontier.calls == 0`, no `llm_judge` in `detector_results`,
          `tier_counts == {"deterministic": 1, "cheap": 0, "escalated": 0}`.
        - US1.2 `"Done."` + `execute_shell` tool call -> `successful is True`, both stubs 0 calls.
        - US2.1 `UNDECIDED`, cheap `success/0.95` -> `successful is True`, reasoning
          `"LLM judge determined attack success: Prefilter LLM judge: r"`, cheap 1 / frontier 0,
          counts `{0, 1, 0}`; the `llm_judge` result's reasoning starts `"Prefilter LLM judge:"`.
        - US2.2 cheap `failure/0.9` -> `successful is False`, reasoning starts
          `"LLM judge determined attack failure: Prefilter"`, frontier 0.
        - US3.1 cheap `success/0.6`, frontier `failure/0.9` -> frontier 1 call, verdict
          `successful`/`score`/`reasoning` equal to a prefilter-disabled pipeline's verdict on the
          same input (same frontier payload), counts `{0, 0, 1}`.
        - US3.2 cheap `ambiguous/0.99`; cheap unparseable `"not json"`; cheap raising
          `RuntimeError("secret-text")`; cheap sleeping past a patched `_LLM_JUDGE_TIMEOUT = 0.05`
          -> each escalates (frontier 1 call); for the raise case the warning log has
          `error_type == "RuntimeError"` and does not contain `secret-text`.
        - US3.3 failure-indicator input + cheap `success/0.99` -> escalates.
        - US3.4 `side_effect_min_confidence=0.95` + `read_file` tool call + cheap `failure/0.99`
          -> escalates.
        - US3.5 `escalate_below=0.5`, cheap `success/0.55` -> escalates (judge gate 0.6).
        - US3.6 #396 ensemble enabled with two member stubs (`judge_clients`) -> on escalation each
          member is called once and the cheap stub once.
        - Counters accumulate over several `evaluate` calls and `tier_counts` returns a copy
          (mutating it does not change the pipeline's counts).
      - `TestDisabled`:
        - no block / `enabled: false` / `disabled={"prefilter"}`: frontier called once per
          `evaluate` with exactly `[{"role": "system", "content": _JUDGE_SYSTEM_PROMPT}, {"role":
          "user", ...}]`, `temperature=0.0`, `max_tokens=256`; verdict equal to a pipeline built
          without any `prefilter_client`; cheap stub 0 calls; `tier_counts == {}`.
        - US4.2: enabled with `llm_client=None`, with `disabled={"llm_judge"}`, and with no
          `prefilter_client` -> one `prefilter_unavailable` warning each (reason as in plan §3),
          `tier_counts == {}`, behaviour as disabled.
- [ ] T004 Implement plan §3 in `ziran/application/detectors/pipeline.py`: `prefilter_client`,
      the init block, `tier_counts`, the step-7 if/else, `_two_tier_judge`,
      `_NO_SIGNAL_REASONING`; update the module and class docstrings (tier order, counters). T003
      passes; `tests/unit/test_detectors.py` and `tests/unit/test_llm_judge.py` pass unmodified;
      `uv run python benchmarks/detection_regression.py` passes.

## Phase 3 — Campaign summary and scan wiring (FR-009, FR-010, US5, US6)

- [ ] T005 Failing tests:
      - `tests/unit/test_scanner.py` (extend): `AgentScanner(MockAgentAdapter(...), config={
        "llm_client": frontier_stub, "detector_config": DetectorConfig(thresholds=...prefilter
        enabled..., prefilter_client=cheap_stub)})`, `run_campaign` over a small phase ->
        `set(result.metadata["judge_tiers"]) == {"deterministic", "cheap", "escalated"}` and the
        sum equals the number of `evaluate` calls (spy on `DetectorPipeline.evaluate`); without
        `detector_config` -> `"judge_tiers" not in result.metadata`.
      - `tests/unit/test_cli_main.py` (extend):
        - `TestDisplayResults`: a `CampaignResult` with `metadata={"judge_tiers": {"deterministic":
          3, "cheap": 2, "escalated": 1}}` -> captured console output contains `Judge Routing` and
          `deterministic 3 · cheap 2 · escalated 1`; without the key -> no `Judge Routing`.
        - `_scan_detector_config` (chdir to `tmp_path`, patch `create_llm_client`): only
          `prefilter: {enabled: true, model: m}` -> returns a config whose
          `thresholds.prefilter.model == "m"`, `prefilter_client` is the patched return value,
          `judge_clients == {}`, and `create_llm_client` was called once with
          `provider=<llm_provider>, model="m", rpm=..., tpm=..., max_retries=...`; with
          `provider: other` -> called with `provider="other"`; both blocks disabled -> `None`;
          `prefilter: {enabled: true}` -> `click.ClickException` naming `prefilter`;
          `create_llm_client` raising `ImportError` -> `click.ClickException` starting
          `"cannot create prefilter client:"`; ensemble disabled with judges listed + prefilter
          enabled -> no member clients created.
        - `scan` with a prefilter-enabled `.ziran/detectors.yaml`, patched client creation and a
          patched `AgentScanner` -> `scanner_config["detector_config"].prefilter_client` set,
          output contains `LLM judge prefilter: m` and no ensemble line.
- [ ] T006 Implement plan §4-§5 in `scanner.py` and `cli/main.py`. T005 passes; existing
      `test_scanner.py` and `test_cli_main.py` tests pass unmodified.

## Phase 4 — Benchmark harness (FR-012, US7)

- [ ] T007 Failing tests:
      - `tests/unit/test_replay_llm_client.py` (extend): `calls` is `0` after construction and
        increments once per `complete`, for recorded and unrecorded responses.
      - `tests/integration/test_two_tier_judging_harness.py` (new, real dataset, offline):
        - `main(["compare", "--json", str(tmp_path / "out.json")])` with `DEFAULT_CASSETTE`
          patched to a nonexistent `tmp_path` file -> exit 0; result JSON has runs `single` and `deterministic_only` only;
          `runs.single.frontier_calls == dataset_size`, `runs.single.tiers == {}`;
          `runs.deterministic_only.accuracy.pipeline.confusion == runs.single.accuracy.pipeline.
          confusion`; `runs.deterministic_only.frontier_calls == tiers["escalated"] ==
          dataset_size - tiers["deterministic"]`; `frontier_calls < dataset_size`;
          `cheap_calls == tiers["escalated"]` (the stub never decides).
        - Synthetic cassette in `tmp_path` (harness check, not an accuracy claim): one verdict per
          example copied from `recorded_judge` (missing -> `ambiguous/0.0`), `model="synthetic"`
          -> exit 0, run `two_tier` present, `tiers["cheap"] > 0`, `two_tier.frontier_calls <
          deterministic_only.frontier_calls`, `two_tier.accuracy.pipeline.confusion ==
          single.accuracy.pipeline.confusion` (cheap verdicts equal the frontier's).
        - Cassette with one example removed -> exit 2 and stderr contains `cassette is stale: 1`;
          `--cassette` to a missing file or to `{"version": 2}` -> exit 2.
        - `record` with `create_llm_client` patched to raise `ImportError` -> exit 2; patched to a
          stub returning `success/0.9` -> exit 0 and the written cassette validates as
          `PrefilterCassette` with one verdict per distinct response; a stub raising inside
          `complete` -> exit 1, no file written.
      - `run_benchmark()` default result has the same detectors and pipeline metrics as before
        (existing `test_detection_accuracy_harness.py` unmodified and green).
- [ ] T008 Implement plan §6: the `calls` counter, `_score(pipeline=...)`, and
      `benchmarks/two_tier_judging.py`. T007 passes. Then run
      `uv run python benchmarks/two_tier_judging.py compare` and commit
      `benchmarks/results/two_tier_judging.json` exactly as produced. Do NOT run `record` unless a
      real cheap model is available; never commit a synthetic cassette.

## Phase 5 — Docs (FR-013)

- [ ] T009 `docs/concepts/detection-pipeline.md`: section `## Two-Tier Judging (prefilter)` after
      #396's ensemble section (after `## Semantic Tier (optional)` if #397 merged): tier order
      diagram, the three routing rules (decided -> no call; cheap decides iff success/failure,
      confidence >= `max(escalate_below, llm_judge_confidence)`, no conflict; else escalate via
      the judge or ensemble), the lean definition, the YAML block, the `judge_tiers` metadata key
      and `Judge Routing` row, the `quality_score` caveat, and that the default `escalate_below`
      is untuned. `docs/reference/benchmarks/detection-accuracy.md`: subsection "Two-tier judging
      comparison": `compare` / `record` usage and the `compare` table copied verbatim from T008's
      run; state that cheap-tier accuracy parity and live call reduction are unverified until a
      real cassette is recorded.

## Phase 6 — Gates

- [ ] T010 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%), `uv run python benchmarks/detection_regression.py`.
      Do not commit `uv.lock` drift. Commit `feat(detectors): two-tier judging with cheap-model
      prefilter` (no `!`, no `BREAKING CHANGE`, no `Co-Authored-By`); PR to `develop` linking
      #398 with the `compare` numbers and SC-004 marked unverified unless a real cassette exists.

## Dependencies
T001 -> T002 -> (rebase on #396) -> T003 -> T004 -> T005 -> T006 -> T007 -> T008 -> T009 -> T010.
T007's replay-counter test is independent and may run any time after T002.
