# Feature Specification: A2A identity probes (card signature, cross-client state, delegated token, look-alike card)

**Feature Branch**: `feat/118-a2a-identity`
**Created**: 2026-11-26
**Status**: Draft
**Input**: plan item F-A2A-IDENTITY. ZIRAN only talks to an A2A agent through chat text. The
`a2a_attacks.yaml` vectors paste a fake card into a message and read the reply. Nothing checks
the agent card's integrity, and nothing tests whether the server keeps one client's state away
from another. `A2AAgentCard` (`ziran/domain/entities/a2a.py`) has no `signatures` field.

## The item in my words

ZIRAN gets six protocol probes for A2A targets. They send their own A2A requests, read the raw
answers and decide with fixed rules: no LLM, no detector. Each probe is a vector in the library
with a new `a2a_probe` key and no prompt, and it yields a normal `AttackResult`.

1. `a2a_card_unsigned`: the agent card has no `signatures`. The evidence holds the card URL and
   the sha256 of the bytes served.
2. `a2a_card_signature_invalid`: the card has signatures, a key is found for them, and none
   verifies over the card (RFC 7515 JWS over the RFC 8785 canonical card without `signatures`,
   as A2A 1.0 says). The key comes from a JWKS the operator pins (`a2a.jwks_url`), or from the
   signature's `jku` when it has the target's origin. With no key, the probe is unmeasured.
3. `a2a_cross_client_context`: client A plants a random code in a new context. Client B sends a
   message with A's `contextId`. B getting the code back (history, artifact or reply) is a
   finding, with both requests as proof.
4. `a2a_cross_client_task`: client A plants the code, client B calls `GetTask` with A's task id.
   B getting the code back is a finding.
5. `a2a_delegated_token_replay`: a token recorded from an earlier session (`a2a.replay_auth`,
   one that should no longer work) sends a message in a new context. The server accepting it is
   a finding. The evidence holds a sha256 prefix of the token, never the token.
6. `a2a_lookalike_card`: for each card URL the operator lists (`a2a.lookalike_cards`, from a
   registry), a card on another origin whose name matches or nearly matches the target's and that
   declares one of its skills is a finding.

Client B is the operator's second credential (`a2a.peer_auth`). On a target with no auth it is a
fresh client with no credential: the `contextId` or task id is then the only thing that guards a
session, and B reading it back is the finding. On a target with auth and no `peer_auth`, the two
cross-client probes are unmeasured: the same credential cannot show a cross-client leak. B
refused with 401 (or no answer) is unmeasured; 403, 404 or a fresh context is isolation held. A probe that lacks
its input, or gets no usable answer, is unmeasured (`outcome: unmeasured`, with the reason under
`skipped` or `error`), never a pass. The probes run only on a target that speaks A2A.

**Acceptance (the item's).**

- Given an A2A server that serves an unsigned card, when `ziran scan --protocol a2a` runs, then a
  finding `a2a_card_unsigned` is raised with the card's sha256.
- Given two clients, when client B sends client A's `contextId` and gets A's history back, then a
  high finding `a2a_cross_client_context` carries both requests as proof.

In my words, as tests on an in-process A2A server (`tests/a2a_servers.py`, a real HTTP server on
127.0.0.1):

- `ziran scan --target t.yaml --protocol a2a --phases reconnaissance` on the server with an
  unsigned card writes a report whose `a2a_card_unsigned` row is successful and whose
  `card_sha256` equals the sha256 of the card bytes the server sent.
- On the server in its vulnerable mode, with no auth, B's request with A's `contextId` gets A's
  message back in the task history. The `a2a_cross_client_context` row is successful, high, and
  its evidence lists A's request and B's request with their context ids. In its safe mode, with
  two credentials (contexts bound to the client), the row is not successful.

## Requirements

- **FR-001** `AttackVector.a2a_probe` takes one of the six probe names. A vector with it has no
  prompt (rejected at load otherwise). `AttackLibrary` passes the key from YAML.
- **FR-002** `A2AAgentCard.signatures` holds the card's JWS signatures (`protected`,
  `signature`, optional `header`).
- **FR-003** `A2AConfig` gains `jwks_url`, `peer_auth`, `replay_auth` and `lookalike_cards`, all
  optional, so existing target YAML loads unchanged.
- **FR-004** A probe vector runs only when the adapter offers an A2A wire
  (`BaseAgentAdapter.a2a_wire`, a domain port; `HttpAgentAdapter` offers one on the A2A
  protocol). The phase executor drops probe vectors on any other target.
- **FR-005** Signature check: algorithms ES256, ES384, RS256 and EdDSA. `none`, HMAC and any other
  algorithm are invalid. A key whose type does not match the algorithm is invalid. A `kid` that
  is not in the JWKS is invalid. A `jku` on another origin is never fetched.
- **FR-006** Requests as another client never carry the target's `auth` or `headers`. Look-alike
  cards and the JWKS are fetched with no credential.
- **FR-007** Probe vectors carry the tags of their category (`authorization`, `bola` or
  `impersonation` on `authorization_bypass`), and the tests that require every vector to have a
  prompt skip `a2a_probe` vectors.
- **FR-008** No change to the detectors, the hybrid judge, role typing, tool aliases,
  `chain_patterns.yaml` or any study ref.

## Assumptions

- `a2a_card_unsigned` is high, not medium. Why: the default scan coverage (`standard`) runs only
  critical and high vectors, and the item's acceptance has the default scan raise it; without a
  signature a client cannot tell a forged card from the real one (A2ASecBench card spoofing).
  Overturned if unsigned cards should only show at `comprehensive` coverage.
- The signature check accepts two canonical forms of the card: RFC 8785 of the card as served,
  and the form the a2a-sdk signer uses (empty values dropped, ASCII escapes). Why: the reference
  SDK's form differs from strict JCS for some cards, and a false "invalid" would be a high
  finding. Overturned if the A2A spec pins one form.
- "Answers the same skills" reads as "declares one of the same skills" (skill id, or name
  ignoring case). Why: it is deterministic; sending the look-alike a chat prompt needs a judge.
- No side-effect goal is attached. Why: these probes' signals are protocol answers (a leaked
  code, an accepted token), not tool calls, and `judge_goal` reads tool calls. Overturned when a
  probe makes the agent run a tool.
- Unconfigured probes (`replay_auth`, `lookalike_cards`, `peer_auth` on an authenticated target)
  read unmeasured, so such a scan reports INCOMPLETE, as spec 113 does for memory vectors on a
  target without memory. Overturned if opt-in probes should be left out of the run instead.
- On a target with no auth, a leak to a fresh anonymous client is a finding. Why: the server then
  treats the id as a bearer capability, which is the A2ABreak cross-client injection; a server
  that wants isolation must bind contexts to an authenticated client. Overturned if anonymous
  targets should read unmeasured instead.
- The phase executor drops probe vectors on another protocol, rather than the library. Why:
  only the executor knows the adapter; `scanner.py` is at its 750-line cap. Two test helpers that
  count a phase's vectors on a mock target now leave probe vectors out.
- The wire sends each probe request once, without the adapter's retries or circuit breaker.
  Why: a probe sends at most three requests, and a failed one is unmeasured, never a pass.

## Out of scope

Acting as a hostile A2A peer (F-A2A-ROGUE-PEER), OAuth2 client-credential tokens for the second
client, an A2A registry client, and a probe for push-notification credentials.
