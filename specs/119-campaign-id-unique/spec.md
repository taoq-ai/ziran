# Spec 119: unique campaign ids

**Status**: Active

## Promise

A campaign id is `campaign_<unix seconds>_<8 hex>`. Two scans started in the same second get different ids, so their probe-marker trace ids (spec 117), checkpoints and log lines differ.

## Acceptance

- Two ids made in one second differ and match `campaign_\d+_[0-9a-f]{8}`.
- Two scans of one vector send different `traceparent` trace ids.
- A resumed scan keeps the id stored in its checkpoint.
- Ids in the old form (`campaign_<unix seconds>`) still load from a checkpoint and render in reports.

## Consumers checked

Checkpoint and resume (id stored and restored verbatim), scan cache (keyed by target and vectors, not the id), report file names and `campaign_*_report.*` globs, HTML report, `export-policy` (sanitises the id for file names), log lines and metrics (opaque label), probe markers (hash of `campaign_id/attack_id`). No parser reads the numeric part. No benchmark or study fixture pins the format.

## Assumptions

The 32-bit suffix is enough: a collision needs two scans in one second and a 1 in 4.3 billion draw.
