# Implementation Plan: A2A identity probes

**Branch**: `feat/118-a2a-identity` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Pydantic v2, httpx (existing), stdlib
`hashlib`/`json`/`base64`/`secrets`/`urllib.parse`. Signature checks use `cryptography`, imported
only when a card is signed; it comes with the `a2a` extra (a2a-sdk, google-auth). No new
dependency.

## Approach

1. Domain. `A2AAgentCardSignature` and `A2AAgentCard.signatures` (`entities/a2a.py`);
   `A2AConfig.jwks_url`, `peer_auth`, `replay_auth`, `lookalike_cards` (`entities/target.py`);
   `A2AProbe` and `AttackVector.a2a_probe`, with a validator that refuses prompts
   (`entities/attack.py`). New port `interfaces/a2a_wire.py`: `A2AWire` (ABC: `get`, `send`,
   `get_task`, `card_url`), `A2AReply` and `A2AClient` (`target`, `peer`, `replay`,
   `anonymous`). `BaseAgentAdapter.a2a_wire` returns None.
2. Infrastructure. `protocols/a2a_wire.py`: `HttpA2AWire` sends `SendMessage` and `GetTask` on
   the HTTP+JSON or JSON-RPC binding, one client per request, built by the adapter's
   `_build_client` from the target config with the chosen client's auth; any client but `target`
   gets no `headers`. `HttpAgentAdapter.a2a_wire` returns one on the A2A protocol.
3. Application. `a2a_probe/probes.py`: `run_a2a_probe(attack, wire)` and the six probes;
   `a2a_probe/jws.py`: base64url, the canonical forms and `verify_card` (ES256, ES384, RS256,
   EdDSA; key type must fit the algorithm). The look-alike probe reuses
   `registry_watch.typosquat_detector.detect`.
4. Hooks. `AttackExecutor._run` sends an `a2a_probe` vector to `run_a2a_probe` with its
   `a2a_wire`; `PhaseExecutor.execute` drops probe vectors when the executor has no wire.
5. Data and docs. `vectors/a2a_identity.yaml` (6 vectors, tag `spec-118`). `a2a_probe` row in
   `docs/concepts/attack-vectors.md`, an "Identity probes" section in
   `docs/concepts/a2a-protocol.md`. Counts: `README.md`, `attack-library.md` (and its file row),
   `atlas-mapping.md`; `benchmarks/generate_all.py` and `regression_check.py --update-baseline`.

## Constitution check

- Hexagonal: the probes import only domain and application modules; the wire is a domain port
  that infrastructure implements and the adapter hands out.
- Type safety: Pydantic models, mypy strict.
- Tests: unit tests for every probe against a real in-process A2A server, the two acceptance
  scenarios as a CLI scan and an `AgentScanner` run.
- Size: `agent_scanner/` modules stay under 400 lines, `scanner.py` is unchanged (749).
- Unchanged: every file under `ziran/application/detectors/`, the hybrid judge, role typing, tool
  aliases, `chain_patterns.yaml` and study refs.

## Test plan

- `tests/a2a_servers.py`: `A2AServer` on `ThreadingHTTPServer` (127.0.0.1, port 0): card
  unsigned, signed (ES256, `jku`) or tampered; JWKS; `SendMessage` and `GetTask` on both
  bindings; bearer tokens, revoked tokens; vulnerable or isolated contexts and tasks.
- `tests/unit/test_a2a_probe.py`: YAML load through `AttackLibrary` (field, prompt refused,
  unknown probe refused); each probe found, clean and unmeasured; bad algorithms, unknown `kid`,
  pinned JWKS, foreign `jku` never fetched; the a2a-sdk canonical form; both bindings; peer and
  replay requests carry only their own credential; the token never in the result.
- `tests/integration/test_a2a_identity_scan.py`: `ziran scan --protocol a2a` raises
  `a2a_card_unsigned` with the card's sha256; a scan raises `a2a_cross_client_context`; a REST
  scan runs no probe vector.
- Fitness: `test_doc_counts.py`, `test_attack_library.py`, `test_authorization_detector.py`,
  `test_atlas_*`, `test_owasp_*`, `test_benchmark_*`, `test_scanner_size.py`, `test_scanner.py`.
