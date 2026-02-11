# Romance Scan Methodology

ZIRAN's Romance Scan is a **multi-phase trust exploitation campaign** inspired by social engineering methodologies. Instead of throwing attacks at an agent randomly, ZIRAN builds trust incrementally — exactly like a real attacker would.

## Why Multi-Phase?

Single-shot prompt injections work against naive agents. But production agents often have:

- **Safety guardrails** that block obvious attacks
- **Context awareness** that detects suspicious behaviour
- **Rate limiting** on sensitive operations

A multi-phase approach overcomes these defences by establishing trust first, then gradually escalating.

## The Eight Phases

### Phase 1: Reconnaissance
Discover what the agent can do — tools, skills, permissions, and data access. This is passive; no attacks are sent.

### Phase 2: Trust Building
Establish conversational rapport. Ask legitimate questions, use the agent as intended. This builds a conversation history that makes later attacks more likely to succeed.

### Phase 3: Capability Mapping
Deep-dive into the agent's capabilities. Discover tool parameters, data schemas, and permission boundaries. Build the knowledge graph.

### Phase 4: Vulnerability Discovery
Probe for weaknesses. Test boundary conditions, try mild prompt injections, and look for information leakage. Use knowledge from previous phases to target probes.

### Phase 5: Exploitation Setup
Position for attack without triggering defences. Craft prompts that leverage discovered capabilities and trust history.

### Phase 6: Execution
Execute the exploit chain. Use knowledge graph paths to guide multi-step attacks through the agent's tool chain.

### Phase 7: Persistence (opt-in)
Test whether the vulnerability survives session resets, memory clears, or agent restarts.

### Phase 8: Exfiltration (opt-in)
Attempt to extract sensitive data through discovered attack paths.

## Knowledge Graph Integration

Each phase updates the **attack knowledge graph** — a directed graph that tracks:

- **Nodes**: Agent capabilities, tools, data sources, vulnerabilities
- **Edges**: Relationships (uses_tool, accesses_data, enables, can_chain_to)

The graph enables ZIRAN to discover attack paths that span multiple phases and tool invocations.
