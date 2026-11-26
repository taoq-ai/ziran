# A2A Protocol Support

ZIRAN supports Google's **Agent-to-Agent (A2A) protocol** — an open standard for agents to communicate and delegate tasks to each other. ZIRAN acts as an A2A client, discovering agent capabilities and scanning them for vulnerabilities.

## What is A2A?

The [Agent-to-Agent protocol](https://github.com/google/A2A) defines a standard way for AI agents to:

- **Advertise capabilities** via Agent Cards
- **Exchange tasks** with structured input/output
- **Report status** through task lifecycle events
- **Authenticate** using standard security schemes

## How ZIRAN Uses A2A

```mermaid
sequenceDiagram
    participant Z as ZIRAN Scanner
    participant A as Target Agent

    Z->>A: GET /.well-known/agent.json
    A-->>Z: Agent Card (skills, auth)
    Z->>Z: Map skills to attack surface
    Z->>A: POST /a2a (send task - Phase 1)
    A-->>Z: Task result
    Z->>Z: Update knowledge graph
    Z->>A: POST /a2a (send task - Phase 2)
    A-->>Z: Task result
    Z->>Z: Detection pipeline verdict
```

### Step 1: Agent Card Discovery

ZIRAN fetches the Agent Card from `/.well-known/agent.json` (or a custom path). The card tells ZIRAN:

- **Agent name and description** — Context for attack generation
- **Skills** — Each skill becomes a testable attack surface
- **Authentication requirements** — How to authenticate requests
- **Protocol version** — A2A specification compliance

### Step 2: Skill-to-Attack Mapping

Each skill in the Agent Card is analyzed:

- Skill descriptions are parsed for sensitive keywords (file access, database, email, etc.)
- Input/output schemas reveal data types that can be fuzzed
- Skills are mapped to relevant attack categories

### Step 3: Multi-Phase Scanning

ZIRAN sends A2A tasks through all scan phases, using the task lifecycle:

| A2A State | ZIRAN Phase |
|-----------|-------------|
| `submitted` | Task sent to agent |
| `working` | Agent processing (streaming) |
| `completed` | Response received, detection pipeline runs |
| `failed` | Error handling, retry logic |

## Configuration

```yaml
# target.yaml
name: "A2A Agent"
url: "https://a2a-agent.example.com"
protocol: a2a

auth:
  type: bearer
  token_env: A2A_API_KEY

a2a:
  agent_card_url: /.well-known/agent.json  # Default path
  use_extended_card: false                  # Extended card features
  enable_streaming: false                   # SSE streaming
```

## A2A-Specific Attack Vectors

ZIRAN includes 11 dedicated A2A attack vectors that test protocol-specific weaknesses:

- **Agent Card manipulation** — Spoofed or malformed cards
- **Skill boundary violations** — Invoking skills outside declared scope
- **Task lifecycle abuse** — Malformed task states, race conditions
- **Cross-agent injection** — Poisoning multi-agent delegation chains
- **Authentication bypass** — Testing security scheme enforcement

These vectors complement the standard 126 vectors, which also apply to A2A agents.

## Identity probes

Six vectors in `a2a_identity.yaml` send their own A2A requests and decide with fixed rules: no
prompt, no LLM and no detector. They run only on an A2A target.

| Vector | Finding |
|---|---|
| `a2a_card_unsigned` | The Agent Card has no signature. The evidence holds the card's sha256. |
| `a2a_card_signature_invalid` | No signature verifies against the trusted key (changed card, unknown `kid`, `none` or HMAC algorithm). |
| `a2a_cross_client_context` | Client B sends client A's `contextId` and gets A's history back. |
| `a2a_cross_client_task` | Client B calls `GetTask` on client A's task and gets it back. |
| `a2a_delegated_token_replay` | A token recorded from an earlier session is accepted in a new context. |
| `a2a_lookalike_card` | A card on another origin has the target's name, or a near copy, and one of its skills. |

They read these optional keys of the target YAML. A probe whose key is unset does not run, and
the scan lists it in a warning, so its outcome is unchanged. A probe that runs and gets no usable
answer (no answer, 429 or 5xx, no `cryptography` to check a signature) reads unmeasured:

```yaml
a2a:
  jwks_url: https://keys.example.com/jwks.json  # the key the card must verify against;
                                                # unset uses the signature's jku on the target's origin
  peer_auth:                                    # client B, a second credential
    type: bearer
    env_var: A2A_SECOND_CLIENT_TOKEN
  replay_auth:                                  # a token that should no longer work
    type: bearer
    env_var: A2A_EXPIRED_DELEGATED_TOKEN
  lookalike_cards:                              # card URLs from a registry
    - https://registry.example.com/agents/travel/.well-known/agent-card.json
```

A request as client B, as the replayed token or for a look-alike card or JWKS never carries the
target's `auth`, `headers` or client certificate, and never follows a redirect. `oauth2`
credentials are not sent, so a probe given one does not run. JWS algorithms other than ES256,
ES384, RS256 and EdDSA read as not allowed. The evidence holds a sha256 prefix of the replayed token, never the
token.

## Install

A2A support requires the `a2a` extra:

```bash
pip install ziran[a2a]
```

## See Also

- [Remote Agent Scanning](remote-scanning.md) — Overview of all remote protocols
- [Google A2A Specification](https://github.com/google/A2A) — Official protocol spec
- [Example: A2A Scan](https://github.com/taoq-ai/ziran/tree/main/examples) — Working A2A examples
