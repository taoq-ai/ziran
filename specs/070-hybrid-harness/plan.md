# Implementation Plan: the harness's hybrid row and routing-share rows

**Branch**: `g11-hybrid-harness` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13), stdlib `argparse`/`json`/`importlib`; reuses the
pin's `ziran.application.hybrid.jobs.judge_traces`, `routed` and `RecordReplayClient` (specs 064
and 067). No new dependencies. Files: `benchmarks/external_eval/{mapping,run,worker}.py`.

## Design

1. `mapping.agentdojo_units`: calls gain `id`; results gain `tool_call_id` and `name`; `Unit`
   gains `user_messages` and `final_answer`, read as the spike's `spike_render.response` reads.
2. `run._worker_unit` passes the two keys and, on an unexcluded payload variant, `judge`
   (`[variant, unit_id]`). `run._args` takes the four hybrid flags; `_hybrid_argv` hands the
   client keyword, the resolved path, the model and the version to the worker.
3. `worker._score` buffers its verdict lines, collects judged units per variant with their
   provenance, and `_judge` runs `judge_traces(share=1.0)` once a variant, then sets `hybrid`,
   the three routing rows and `llm` (the cause), and counts band, outcomes and
   `_mask_changed` (the render with the mask off differs). The end line carries the counts.
4. `run.run` refuses a hybrid run where no pin judged; a record run prints the counts and
   returns before any metric; a replay run records the model, client version and replies
   sha256. `_metrics` scores each predictor on the variants that have it.
5. `_assert_linear` uses `time.process_time` and a best-of-three rule with a 12x early fail.

## Constitution check

Typed (mypy strict on `ziran/`, unchanged), tests first, no new dependency, no model call.
