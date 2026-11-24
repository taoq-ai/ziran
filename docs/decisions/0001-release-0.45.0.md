# 0001: Release ziran v0.45.0

## Context

develop holds 20 first-parent merges not yet on main, among them the release
hygiene fixes (#553) and the steering credential-file fix (#554). No commit in
the range is marked breaking. Merging the release-please PR tags v0.45.0, and
the tag runs `release.yml`, which publishes to PyPI.

## Decision

Cut v0.45.0 from develop through `release/0.45.0` into main, by the gitflow
release process.

## Consequences

- v0.45.0 is the first release with provenance and SBOM attestations
  (`SECURITY.md`, "Verifying a release").
- Audit baselines that hold a `Read(/etc/shadow)` pair with an outbound tool
  now show a critical `secret_file_exfiltration` chain and need re-recording.
- A PyPI publish cannot be undone. Rollback is a yank of 0.45.0 on PyPI plus
  a revert on main and develop.

## Owner's answer

Asked on 2026-11-24, "cut ziran v0.45.0 now?". The owner answered "Go".
