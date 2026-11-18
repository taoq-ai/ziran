Verdict: PASS
Gate: arch
Item: ISSUE-275-PAIR-SPIKE
PR: taoq-ai/ziran#519
Head: 194e95e09001cbacbd400520e5c6b82709c465aa
Confidence: high
Breaking: no (docs-only spike; the planned slice adds optional fields and an opt-in phase extension, a minor)

## Findings
- [low] blocks: no. plan.md section 3, guarantee bullet 1: "if static work alone overruns phase_timeout, the phase drops static vectors today and still does" understates the design. The probe shows the extension hands PAIR's time to the static overrun (100 of 100 static recorded against 70 without PAIR), and the PAIR vectors are then clamped to the phase end. Reword it as "static vectors get at least their no-PAIR time; PAIR vectors take what is left".
- [low] blocks: no. Slot order is preserved, but up to c-1 static vectors still running when the first PAIR vector starts share the judge client's rate limiter (infrastructure/llm/factory.py) and the target with it. Those tail vectors can be slowed toward their 60 s `attack_timeout`. "At the same times" holds for acquiring a slot, not for finishing.
- [low] blocks: no. scanner.py:696, the backward-compatible `_execute_phase`, builds a second `AttackExecutor` and `PhaseExecutor` without budget or cache. PR 2 must give it the attacker and budget too, or a PAIR vector run through it gets the "no attacker" error result.
- [low] blocks: no. The CLI `--phase-timeout` help and the `phase_timeout` docstring (scanner.py:147) describe a fixed cap. PR 2 should say it extends for PAIR vectors, so an operator sizing a CI job's wall clock reads it there and not only in the `phase_timeout_extended` log.

## Probes
- Delta: `git diff --stat e2bf7c7 194e95e` shows spec.md, plan.md, tasks.md and research.md only. The spike blobs are unchanged, so the round-1 byte-identical reproduction holds, and no file under ziran/, tests/ or benchmarks/ changed. PR #519 head was read once: 194e95e.
- Scaled model of plan.md section 3 at this head (`timeout 120 uv run --no-project --python 3.11|3.12|3.13 python -I deadline2.py`): stable sort of PAIR last, timer `phase + ceil(k/c) * T`, deadline taken inside the semaphore, backstop at `deadline + GRACE`, scaled 1 unit = 100 s. All five cases gave the same result on 3.11.15, 3.12.13 and 3.13.14:
  - B1, 5 PAIR + 60 static, c=5: static 60/60 (no-PAIR 60), all 5 PAIR `timeout`, none unrecorded.
  - B2, 70 interleaved vectors with mixed durations and early PAIR successes, c=5: 60/60 static (no-PAIR 49).
  - B3, c=1: 8/8 static.
  - B4, static overrun: 100/100 static (no-PAIR 70), PAIR clamped to `timeout`.
  - B5, the B005 shape (c=2, 2 PAIR first, 6 static): 6/6 static, both PAIR recorded, phase not cut.
  - In every case each static vector acquired its slot before any PAIR vector, and its acquire time matched the no-PAIR run within 0.03 for every vector both runs acquired. 0 vectors went unrecorded.
- FIFO under gather: `gather` creates the tasks in argument order, and `_run_attack`'s first await is `async with semaphore` (phase_executor.py:204), so tasks join the waiter queue in list order. No task arrives late, so the 3.11 barging case (a new acquirer taking a slot just released to a waiter) cannot occur. The B005 order assertion keeps this checked in CI.
- Extension bound: every PAIR vector holds a slot for at most T, and slots are free by the time static work ends (at most phase_timeout). Greedy list scheduling therefore finishes the k-th PAIR vector by phase_timeout + ceil(k/c) * T. The clamp to the phase end minus GRACE covers the rest (B3 used 8.81 of 10.2).
- Anything else that assumes 300 s: nothing.
  - `git grep phase_timeout` outside specs and tests finds only phase_executor.py:71/80/317/323, scanner.py:129/157/278/710, the CLI plumbing and its `attack_timeout > phase_timeout` warning (main.py:1964, unaffected because 240 < 300), and ui Settings.tsx:102 passing the value through.
  - Nothing wraps `run_campaign` in a timeout: web run_manager.py:142 has none and action.yml has none.
  - The only `asyncio.timeout` calls elsewhere are per-judge-call timers (pipeline.py:275/328/352, ensemble.py:120).
- closed: PAIR slot starvation of queued static vectors (spec.md:126) at 194e95e. US2.3 now states the guarantee and its limits, and the scaled model holds it.
- closed: B005 GRACE inconsistency (tasks.md:54) at 194e95e. `PAIR_GRACE_SECONDS` is patched to 0.05 and the phase timeouts sit above it.
- closed: release window between the PRs at 194e95e. `TacticType.PAIR`, the `tactic` description and the dispatch all land in PR 2.
- closed: `track()` double count at 194e95e. FR-002 puts the warning in the `attacker_llm_client` docstring.
- closed: where the deadline is taken at 194e95e. It is now taken inside `async with semaphore` (FR-004), and B005 tests that queue time is not charged.
- Earlier closures stand: phase-timeout cancellation, layering, cache and seed (all closed at e2bf7c7).
- Confidence high: every claim was checked against code at c5d75eb, and the scheduling guarantee was run on all three CI Python versions.

## Residual risk
Live latency is unmeasured, so the 240 s default and the size of the phase extension rest on code-derived bounds. A phase with many PAIR vectors can run for a long time (at c=1, k PAIR vectors add k x 240 s), which the cost warning must name.
