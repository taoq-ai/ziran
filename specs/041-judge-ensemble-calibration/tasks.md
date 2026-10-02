# Tasks: LLM judge ensemble with confidence calibration

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM, no API keys: every judge is an
`LLMJudgeDetector` over a stub `BaseLLMClient` returning canned judge JSON (reuse the
`_make_mock_client` pattern of `tests/unit/test_llm_judge.py`; `SlowLLMClient` /
`FailingLLMClient` of `tests/unit/test_detectors.py` for timeout / error). New tests carry
`@pytest.mark.unit`. Names, config keys, fields and evidence keys are exactly those in
[plan.md §Public contract](plan.md#public-contract). Existing tests MUST NOT be modified: they are
the "disabled = unchanged" regression net.

Shared test helper (in `tests/unit/test_judge_ensemble.py`, not a new module):
`_judge(verdict: str, confidence: float, **quality) -> LLMJudgeDetector` wrapping a stub client
whose `complete` returns `{"verdict": ..., "confidence": ..., "reasoning": "r"}` (plus quality keys
when given), and `_ensemble(*judges, **kw) -> EnsembleJudge` naming members `j0`, `j1`, ...

## Phase 1 — Entities and config block (FR-001, FR-002, FR-011)

- [ ] T001 [P] Failing tests:
      - `tests/unit/test_judge_ensemble.py::TestEntities`: `JudgeVote` accepts the four verdicts,
        rejects `"maybe"` and `score=1.5`; `DetectorResult(...)` without the new fields has
        `needs_review is False`, `agreement is None`, `judge_votes == []`;
        `DetectionVerdict(successful=False, score=0.0).needs_review is False`.
      - `tests/unit/test_detector_thresholds.py` (extend): `DetectorThresholds().ensemble.enabled is
        False`; `EnsembleConfig(enabled=True, judges=[...1 judge])`, duplicate names,
        `min_margin=3` with 2 judges, `min_margin=0`, `needs_review_below=1.5`, unknown key, and
        `JudgeMemberConfig(name="x", provider="openai")` each raise `ValidationError`;
        `EnsembleConfig(enabled=False, judges=())` is valid; `judges` given as a list is stored as a
        tuple; the model is frozen.
      - `tests/unit/test_detectors_config.py` (extend): a `tmp_path` YAML with a valid `ensemble`
        block loads via `load_detector_thresholds`; `ensemble: {enabled: true, judges: [{name:
        a}]}` raises `DetectorConfigError` whose message starts with the path and contains
        `ensemble`; a file with only flat thresholds still loads with the ensemble disabled.
      Confirm they fail (`ImportError` / `AttributeError`).
- [ ] T002 Implement: `JudgeVote` and the four new fields in `ziran/domain/entities/detection.py`;
      `JudgeMemberConfig` / `EnsembleConfig` (with validators) in the new
      `ziran/application/detectors/ensemble.py` (module docstring: purpose, tier order, formula);
      the `ensemble` field on `DetectorThresholds`. T001 passes; mypy strict clean.

## Phase 2 — `EnsembleJudge` and framing (FR-003..FR-010, US1-US3)

- [ ] T003 [P] Failing tests in `tests/unit/test_llm_judge.py` (extend, new class
      `TestFraming`): `LLMJudgeDetector(client)` sends a system message equal to
      `_JUDGE_SYSTEM_PROMPT` (and `_QUALITY_JUDGE_SYSTEM_PROMPT` with `quality_scoring=True`) with
      `temperature=0.0`, `max_tokens=256` / `512` (pins today's call); `framing="Be strict."` sends
      `_JUDGE_SYSTEM_PROMPT + "\nBe strict."` and the same user message.
- [ ] T004 Implement the `framing` kwarg (plan §3). T003 passes; all existing
      `test_llm_judge.py` tests pass unmodified.
- [ ] T005 Failing tests in `tests/unit/test_judge_ensemble.py`:
      - `TestAggregation`: spec US1.1 (2-judge split: `score 0.5`, `confidence 0.0`, `agreement
        0.0`, `needs_review`, votes `[("j0","success"),("j1","failure")]`, reasoning contains
        `j0=success` and `j1=failure`); US2.1 (3x success 0.8 -> `approx(3.4/3.5)`,
        `agreement 1.0`, no review, `matched_indicators == ["llm_judge_verdict"]`); US2.2 (2-1 ->
        `score 1.0`, `approx(1.4/3.5)`, `approx(1/3)`, review); US2.4 (3x failure -> `score 0.0`,
        same confidence as US2.1, `matched_indicators == []`); US3.1 (2/2 tie); US3.2
        (ambiguous + unparseable + success 0.9 -> `approx(1.45/3.5)`, two `ambiguous` votes);
        US3.5 (`min_margin=2`, 2-1 -> `score 0.5`, review); every row of plan §2's worked table;
        `detector_name == "llm_judge"` always.
      - `TestMonotonic`: parametrised over n in {2, 3, 5}, every `(s, f)` with `s + f <= n`, and
        member confidences in {0.0, 0.5, 1.0} (uniform per outcome): for any two outcomes with
        `|s1-f1| > |s2-f2|`, `confidence1 > confidence2`; every confidence in `[0, 1]`;
        unanimous > split > tie explicitly asserted for n = 3.
      - `TestQuality`: with `quality_scoring=True` members returning quality keys, the result's
        `quality_score` is the component-wise mean; members without quality keys are skipped;
        none present -> `None`.
      - `TestFailures`: US3.3 (member client sleeps 1 s, `timeout=0.05`, other returns failure:
        slow vote `"error"`, `confidence 0.0`, reasoning contains `timed out`; the call completes in
        well under 1 s; the failure vote is kept); US3.4 (client raises `RuntimeError` -> that vote
        `"ambiguous"`, no exception); a member whose `detect` itself raises (monkeypatched) ->
        `"error"` vote with `RuntimeError` in reasoning; all members erroring -> `score 0.5`,
        `confidence 0.0`, review.
      - `TestBuildJudge`: `build_judge(client)` and `build_judge(client, ensemble=EnsembleConfig())`
        return `LLMJudgeDetector`; enabled config returns `EnsembleJudge` whose members without
        `model` use `client` and with `model` use `judge_clients[name]` (assert via which stub's
        `complete` was awaited); a member with `model` missing from `judge_clients` -> `ValueError`
        naming the judge; members receive `framing` and `quality_scoring`.
      - `TestReviewEvidence`: verdict whose `llm_judge` result has no votes -> `{}`; verdict
        without an `llm_judge` result -> `{}`; ensemble verdict -> exactly the three keys with
        `judge_votes` as plain dicts.
- [ ] T006 Implement `EnsembleJudge`, `build_judge`, `review_evidence` per plan §2 (aggregation
      rules 1-10). T005 passes; mypy strict clean.

## Phase 3 — Pipeline (FR-012, US1.2, US4)

- [ ] T007 Failing tests in `tests/unit/test_detectors.py` (extend, new class
      `TestJudgeEnsemblePipeline`; existing classes untouched):
      - `DetectorPipeline(llm_client=c)` -> `_llm_judge` is an `LLMJudgeDetector`; with
        `DetectorConfig(thresholds=DetectorThresholds(ensemble=<enabled 2 judges>))` -> an
        `EnsembleJudge`; with `disabled={"llm_judge"}` -> `None` and `await pipeline.judge(...) is
        None`; without a client -> `judge(...)` returns `None`.
      - `judge()` in single mode returns the same `DetectorResult` as `evaluate` appends; on a slow
        client with `_LLM_JUDGE_TIMEOUT` patched to 0.01 returns `None` (mirrors the existing
        timeout test).
      - US1.2: split ensemble + a neutral response -> `verdict.successful is False`,
        `verdict.needs_review is True`, the `llm_judge` detector result has two votes.
      - Unanimous success ensemble (confidence 0.9) + neutral response -> `successful is True`,
        reasoning starts with `"LLM judge determined attack success"`, `needs_review is False`.
      - Refusal response + split ensemble -> `successful is False`, reasoning starts with
        `"Refusal detected"`, `verdict.needs_review is False`.
      - US4.2: single-judge verdict `needs_review is False`; its `llm_judge` result has
        `agreement is None`, `judge_votes == []`.
- [ ] T008 Implement plan §4 in `ziran/application/detectors/pipeline.py`: `judge_clients` field,
      `build_judge` in `__init__`, public `judge()`, the step-6 call, `needs_review=review` on the
      three `_resolve` returns. T007 passes; the full existing `tests/unit/test_detectors.py`,
      `test_pipeline_thresholds.py`, `test_refusal_multilingual.py` pass unmodified.

## Phase 4 — Evidence and scan wiring (FR-013, FR-014, US1.3, US5)

- [ ] T009 Failing tests:
      - `tests/unit/test_scanner.py` (extend): `AgentScanner(adapter=MockAgentAdapter(...),
        config={"llm_client": stub, "detector_config": DetectorConfig(thresholds=
        DetectorThresholds(ensemble=<enabled, judges a/b>))})` builds an ensemble pipeline; a
        campaign/attack whose response is neutral and whose judges split yields an unsuccessful
        `AttackResult` whose `evidence` has the original `note` plus `needs_review: True`,
        `judge_agreement: 0.0`, two `judge_votes`; with a unanimous-success ensemble the successful
        evidence carries the three keys; with no `detector_config` (single judge) the success and
        failure evidence key sets equal today's (`{"response_snippet", "tool_calls",
        "matched_indicators", "detector_scores", "detector_reasoning", "side_effects"}` /
        `{"note"}`).
      - `tests/unit/test_tactics.py` (extend): the same three cases for a multi-turn vector
        (failure keys `{"note", "tactic", "turns_attempted"}` in single mode).
      - `tests/unit/test_cli_main.py` (extend, class `TestScanDetectorConfig`, monkeypatch
        `ziran.infrastructure.llm.create_llm_client` to a recorder returning stubs, `chdir` to
        `tmp_path`): no `.ziran/detectors.yaml` -> `None`; ensemble disabled -> `None`; enabled with
        `primary` + `second` (`model: m2`) -> `DetectorConfig` whose `thresholds.ensemble` equals
        the file's block, other thresholds at defaults even if the file overrides `hit`, and
        `judge_clients == {"second": <stub>}` created with `provider="litellm"`, `model="m2"` and
        the passed rpm/tpm/retries; invalid file -> `click.ClickException` containing
        `ensemble`; recorder raising -> `click.ClickException`.
- [ ] T010 Implement plan §6 (`attack_executor.py`, `tactics.py`) and §7 (`scanner.py`
      passthrough, `_scan_detector_config` and its call in `scan`). T009 passes; existing
      `test_scanner.py`, `test_tactics.py`, `test_expanded_tactics.py`, `test_cli_main.py` pass
      unmodified.

## Phase 5 — Docs (FR-015)

- [ ] T011 `docs/concepts/detection-pipeline.md`: add an "LLM judge ensemble" section after
      "Confidence Scoring": where the judge sits in the tier order (deterministic -> semantic ->
      prefilter -> judge), the YAML block of plan §5 with every key and default, the vote / margin
      / confidence rules and the worked table of plan §2 (values computed, not measured),
      `needs_review` semantics (advisory; `successful` and exit codes unchanged), the evidence keys
      of plan §6, the cost note (`len(judges)` calls per evaluated prompt), that only `ziran scan`
      reads the block and only when `--llm-provider` / `--llm-model` is set, and
      `DetectorPipeline.judge` as the programmatic entry point. Do not touch the unrelated sections.

## Phase 6 — Gates

- [ ] T012 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%), and `uv run python benchmarks/detection_accuracy.py`
      compared with `benchmarks/results/detection_accuracy_baseline.json` (must be within
      tolerance; record the actual command output in the PR, do not restate numbers from memory).
      Do not commit `uv.lock` drift or a regenerated baseline. Commit
      `feat(detectors): LLM judge ensemble with confidence calibration` (no `!`, no
      `BREAKING CHANGE`, no `Co-Authored-By`); PR to `develop` linking #396.

## Dependencies
T001 -> T002 -> (T003 -> T004) -> T005 -> T006 -> T007 -> T008 -> T009 -> T010 -> T011 -> T012.
T001 and T003 are independent test-writing tasks ([P]). T005 needs T002 (models) and T004
(`framing`). Sibling branches (#397, #398) touch `pipeline.py` and `thresholds.py`; rebase on
`develop` before T008 if either has merged and keep the step-6 call shape of plan §4.
