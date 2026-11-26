# Implementation Plan: per-probe correlation markers

**Branch**: `feat/117-probe-markers` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Pydantic v2, stdlib `contextvars`, `hashlib`,
`urllib.parse`; httpx request event hooks (already a dependency). No new dependency.

## Approach

1. `ziran/domain/entities/target.py`: `probe_markers: Literal["traceparent", "header", "both"] |
   None = None`.
2. `ziran/domain/entities/attack.py`: `ProbeMarker` (probe id, trace id, sent at) and
   `AttackResult.probe_markers: list[ProbeMarker]`, defaulted empty.
3. `ziran/domain/probe_markers.py`: `probe_scope(campaign_id, attack_id)` sets a context variable
   holding the attack's marker list; `mark_probe(mode)` appends the next turn's marker and returns
   its headers, or `{}` when off or outside an attack. Trace id: the first 32 hex digits of
   sha256 of `<campaign>/<vector>`; parent id: the first 16 of sha256 of the probe id. The probe
   header value is percent-encoded so a non-ASCII vector id cannot break the request.
4. `HttpAgentAdapter`: when `probe_markers` is set, `_build_client` adds one async request hook
   that copies the current task's marker headers onto each request. `invoke` and `stream` set
   those headers for the call from `mark_probe` and reset them after. All four protocol handlers
   send through this one client, so none of them changes.
5. `AttackExecutor(campaign_id=...)`; `execute` opens the scope around the whole attack (single,
   tactic, PAIR and carrier paths) and copies the markers onto the result. `AgentScanner` passes
   its campaign id.
6. `docs/guides/remote-agents.md`: a "Probe Markers" section.

## Freeze check

No file under `ziran/application/detectors/`, `ziran/application/hybrid/`, role typing, tool
aliases or `chain_patterns.yaml` changes.
