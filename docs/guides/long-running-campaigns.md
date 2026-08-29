# Long-running campaigns: checkpoint and resume

Comprehensive campaigns against large models can run for a long time. A single
phase at `--coverage comprehensive` can take tens of minutes. `ziran scan`
checkpoints its progress so an interrupted campaign (OOM kill, CI timeout,
laptop sleep, Ctrl-C) can pick up where it stopped instead of starting over.

## How checkpointing works

A checkpoint is a single JSON file at `<output-dir>/.checkpoint.json`. It records
the completed phases, the accumulated attack results, and the set of attack
vectors that have already been tested. Writes are atomic (temp file then
`os.replace`), so a crash mid-write never leaves a corrupt checkpoint: either the
previous checkpoint or the new one is present, never a truncated file.

Checkpointing is always on during a scan. The file is removed automatically when
a campaign completes successfully.

### Between-phase and partial-phase resume

The scanner checkpoints after every completed phase, and also incrementally
*within* a phase as individual vectors finish. That means a crash partway
through a long phase does not throw away the whole phase: on resume, the phase
re-enters and every vector already recorded in the checkpoint is skipped, so only
the not-yet-attempted vectors run.

## Resuming

Point `--resume` at the same `--output` directory the interrupted run used:

```bash
ziran scan --target ./target.yaml --coverage comprehensive --output ./run1
# ... process is killed partway through ...
ziran scan --target ./target.yaml --coverage comprehensive --output ./run1 --resume
```

If `--resume` is given but no checkpoint exists in the output directory, the scan
starts fresh with a warning.

## Tuning the flush interval

Incremental writes are throttled so the safety net does not become the
bottleneck: a checkpoint is flushed after a fixed number of completed vectors or
after a time interval, whichever comes first. The time interval is configurable:

```bash
ziran scan --target ./target.yaml --checkpoint-flush-interval 30
```

- Lower values (e.g. `5`) checkpoint more often. Resume loses less work after a
  crash, at the cost of more frequent writes.
- Higher values (e.g. `60`) reduce write frequency for very fast phases.
- Default: 10 seconds, with a completion-count backstop that also flushes
  periodically regardless of the interval.

Whatever the interval, at most the vectors completed since the last flush are
re-run on resume.

## Overhead

Building and atomically writing a checkpoint costs on the order of ~1 ms even for
a large campaign (hundreds of accumulated results). Because writes are throttled
rather than per-vector, the overhead stays well under the 5% budget for realistic
phases where each attack takes hundreds of milliseconds or more. In the
partial-phase resume integration test, flushing on *every* one of ten vectors
still completes the phase in well under a second.

## Notes

- Checkpoints written by older versions (between-phase only) still load and
  resume: the file format is unchanged, and partial resume rides the existing
  `tested_vector_ids` field.
- Token totals in a mid-phase checkpoint may slightly undercount the in-progress
  phase; the count is corrected at phase completion. This does not affect which
  vectors are skipped on resume.
