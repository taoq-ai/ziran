# Multi-Phase Trust Exploitation

ZIRAN's core methodology is a **multi-phase trust exploitation campaign** inspired by social engineering. Instead of throwing attacks at an agent randomly, ZIRAN builds trust incrementally — exactly like a real attacker would.

!!! danger "Why this matters"

    Real attackers don't send `"Ignore all instructions"` as their opening message.
    They build rapport, discover capabilities, and **chain** multiple steps together.
    ZIRAN replicates this real-world approach automatically.

## Why Multi-Phase?

Single-shot prompt injections work against naive agents. But production agents often have:

- **Safety guardrails** that block obvious attacks
- **Context awareness** that detects suspicious behaviour
- **Rate limiting** on sensitive operations

A multi-phase approach overcomes these defences by establishing trust first, then gradually escalating. The difference in detection rate is dramatic:

| Approach | Typical Detection Rate | Against Hardened Agents |
|----------|----------------------|------------------------|
| Single-shot injection | 40–60% | 10–20% |
| **Multi-phase campaign** | **80–95%** | **60–80%** |

## The Eight Phases

```mermaid
graph LR
    P1[1. Reconnaissance] --> P2[2. Trust Building]
    P2 --> P3[3. Capability Mapping]
    P3 --> P4[4. Vulnerability Discovery]
    P4 --> P5[5. Exploitation Setup]
    P5 --> P6[6. Execution]
    P6 --> P7[7. Persistence]
    P7 --> P8[8. Exfiltration]

    style P1 fill:#4051B5,color:#fff
    style P2 fill:#4051B5,color:#fff
    style P3 fill:#4051B5,color:#fff
    style P4 fill:#E53935,color:#fff
    style P5 fill:#E53935,color:#fff
    style P6 fill:#E53935,color:#fff
    style P7 fill:#FF9800,color:#000
    style P8 fill:#FF9800,color:#000
```

### Phase 1: Reconnaissance
Discover what the agent can do — tools, skills, permissions, and data access. This is passive; no attacks are sent. For remote agents, ZIRAN reads endpoint metadata, OpenAPI specs, or A2A Agent Cards.

### Phase 2: Trust Building
Establish conversational rapport. Ask legitimate questions, use the agent as intended. This builds a conversation history that makes later attacks more likely to succeed.

### Phase 3: Capability Mapping
Deep-dive into the agent's capabilities. Discover tool parameters, data schemas, and permission boundaries. Build the [knowledge graph](knowledge-graph.md).

### Phase 4: Vulnerability Discovery
Probe for weaknesses. Test boundary conditions, try mild prompt injections, and look for information leakage. Use knowledge from previous phases to target probes.

### Phase 5: Exploitation Setup
Position for attack without triggering defences. Craft prompts that leverage discovered capabilities and trust history.

### Phase 6: Execution
Execute the exploit chain. Use knowledge graph paths to guide multi-step attacks through the agent's [tool chain](tool-chains.md).

### Phase 7: Persistence (opt-in)
Test whether the vulnerability survives session resets, memory clears, or agent restarts.

### Phase 8: Exfiltration (opt-in)
Attempt to extract sensitive data through discovered attack paths.

## Coverage Levels

The `--coverage` flag controls how many phases ZIRAN runs:

| Level | Phases Included | Use Case |
|-------|----------------|----------|
| `essential` | 1–4 (Recon → Vulnerability Discovery) | Quick feedback during development |
| `standard` | 1–6 (Recon → Execution) | Pre-deployment gate (**default**) |
| `comprehensive` | 1–8 (All phases) | Full security audit |

```bash
# Quick check
ziran scan --target target.yaml --coverage essential

# Full audit
ziran scan --target target.yaml --coverage comprehensive
```

## Knowledge Graph Integration

Each phase updates the **attack knowledge graph** — a directed graph that tracks:

- **Nodes**: Agent capabilities, tools, data sources, vulnerabilities
- **Edges**: Relationships (`uses_tool`, `accesses_data`, `enables`, `can_chain_to`)

The graph enables ZIRAN to discover attack paths that span multiple phases and tool invocations. See [Knowledge Graph](knowledge-graph.md) for details.

## How It Compares

| Feature | ZIRAN | Single-Shot Tools |
|---------|-------|------------------|
| Phase-aware campaigns | :white_check_mark: 8 phases | :x: 1 phase |
| Trust escalation | :white_check_mark: Automatic | :x: None |
| Knowledge graph | :white_check_mark: Builds per-phase | :x: N/A |
| Tool chain reasoning | :white_check_mark: Graph-based | :x: None |
| Coverage control | :white_check_mark: 3 levels | :x: All or nothing |
