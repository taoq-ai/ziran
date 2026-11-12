# Spec 068: linear-time provenance patterns and reserved metadata keys

**Status**: Active · **Item**: G10-HARDEN (goal G-11) · **Date**: 2026-11-12

## The item in my words

Two hardening fixes before the fresh run.

1. The mail and domain patterns in `provenance._PARTS`, and the CamelCase split in `tokens()`,
   retry a long run from every start, so a 64k-character argument took 41 s and a 100k-character
   tool name took 95 s. They become linear-time patterns that return exactly what the old ones
   return on every input. A seeded differential test over 300,000 random inputs proves it, with
   0 differences. The probe-parity tests stay green.
2. `trusted_task`, `tool_results` and `payload` are the caller's inputs to the side-effect
   detector. A target can return them in its metadata and so steer the verdict. They are dropped
   from target-supplied metadata on the HTTP adapter's invoke and stream paths and in the attack
   executor, which covers every adapter in a scan.

## Acceptance

- Given a 1 MB argument, when `provenance()` runs, then it finishes in under 1 s.
- Given a 1 MB tool name, when `tokens(canonical_tool_name(name))` runs (the work of
  `tool_roles()`), then it finishes in under 1 s. `tool_roles()` itself is timed once spec 066
  (ziran#492) lands; until then that test skips.
- Given 300,000 seeded random inputs with adversarial shapes, when the new and old patterns run,
  then their findall results and token lists differ on 0 inputs.
- Given metadata holding the three keys, when it reaches the detectors through
  `HttpAgentAdapter.invoke`, `HttpAgentAdapter.stream`, or `AttackExecutor` (single, streaming
  and multi-turn), then the three keys are gone and the rest is kept.
- One constant, `RESERVED_METADATA_KEYS` in `ziran/domain/interfaces/adapter.py`, names the
  keys; a test holds it equal to the keys `provenance()` reads.

## Out of scope

The item's promise also names the harness `unit_id` pattern check and the `--pin` name test.
Both are code of ziran#493 (spec 065), not on develop; they belong on that branch.

## Assumptions

- The URL, id and number patterns stay as they are: on 1 MB of each adversarial shape they run
  in under 0.2 s (measured), so they are already linear. Overturned by a shape that is slow.
- `classify_tool()` is linear but takes about 0.65 s on a 1 MB name, so `provenance()` with a
  1 MB tool name is near the 1 s bound. It is not a regex of this item; left as a candidate.
- The multi-turn path (`TacticExecutor`) is part of the executor's invoke path, so it strips too.
