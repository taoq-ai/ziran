# Implementation Plan: linear-time provenance patterns and reserved metadata keys

**Branch**: `feat/068-harden` | **Date**: 2026-11-12 | **Spec**: [spec.md](spec.md)

## Summary

Regex lines only in `provenance.py`, plus the strip on each path.

- CamelCase: `([A-Z]+)([A-Z][a-z])` becomes `([A-Z])([A-Z][a-z])`. A match starts at the last
  capital of a run, as the old greedy backtrack ended there, and the `\1 \2` replacement stays.
- Mail: `(MAIL)|[\w.+-]+`. Every start inside one `[\w.+-]` run reaches the same `@`, so when
  the run's first start fails all later ones fail; the second branch consumes the run. Its
  findall item is empty and `atoms()` drops it.
- Domain: `(DOMAIN)|\b(?:[a-z0-9-]+\.?)+`. A later start in the same dotted chain can only
  match where the chain's first word-boundary start would, so the second branch consumes the
  chain. It keeps the `\b`, since a start that fails on `\b` alone says nothing of later ones.
- `PROVENANCE_METADATA_KEYS` and `drop_reserved()` in `ziran/domain/interfaces/adapter.py`, so
  the infrastructure and application layers both import it from the domain. The constant, its
  comment, the import line and the `HttpAgentAdapter.invoke` strip are the exact lines of
  ziran#493 (spec 065), so either PR merges after the other without a conflict.

## Constitution Check

- Hexagonal: the constant is in the domain port module; adapters and the executor import it
  inward. PASS
- No new dependencies. PASS
- `attack_executor.py` stays under the 400-line limit (399). PASS
