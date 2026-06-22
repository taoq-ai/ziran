# Knowledge Graph

## Why a Graph?

During a scan, ZIRAN discovers tools, permissions, data sources, and their relationships. A flat list of findings loses the connections between them -- you see that `read_file` exists and `http_request` exists, but not that they can chain together into a data exfiltration path.

A directed graph preserves these relationships. Each discovery becomes a node, each relationship an edge. As the scan progresses, the graph grows and reveals attack paths that only become visible after enough context is gathered -- a tool discovered in phase 1 might combine with a permission found in phase 4 to create a vulnerability neither phase would catch alone.

The graph also drives adaptive campaigns: after each phase, the strategy examines the graph to decide which phase to run next.

## Implementation

ZIRAN uses a **NetworkX-based directed multigraph** to track all discoveries, relationships, and attack paths during a scan campaign.

## Node Types

| Type | Icon | Description |
|------|------|-------------|
| `agent` | :star: | An agent in a multi-agent topology |
| `capability` | :gear: | A discovered agent capability |
| `tool` | :wrench: | An invokable tool the agent has access to |
| `vulnerability` | :warning: | A discovered vulnerability |
| `data_source` | :file_folder: | A data source the agent can access |
| `phase` | :repeat: | A scan phase execution |
| `agent_state` | :robot: | A snapshot of agent state |

## Edge Types

| Type | Description |
|------|-------------|
| `uses_tool` | Agent uses this tool |
| `accesses_data` | Capability accesses a data source |
| `trusts` | Trust relationship between entities |
| `enables` | One capability enables another |
| `can_chain_to` | Tool can chain to another tool |
| `discovered_in` | Vulnerability discovered in a phase |
| `exploits` | Attack exploits a vulnerability |
| `leads_to` | One state leads to another |
| `delegates_to` | One agent delegates work to another (multi-agent) |
| `shares_context` | One agent shares context/data with another (multi-agent) |
| `trust_boundary` | A trust boundary between two agents (multi-agent) |

## Visualization

The knowledge graph renders interactively with **vis-network**, and the **web UI and the self-contained HTML report share a single styling/mapping spec** so both surfaces look and behave identically. (The report is standalone — the only network dependency is the vis-network library from a CDN; no backend access is required.)

### Layout modes

Switch how the graph is arranged:

- **Force** — physics-based force-directed layout (the classic view).
- **By phase** — a hierarchical, left-to-right layout that bands nodes by the campaign phase they were discovered in (reconnaissance → … → exfiltration), so the structure reads as a story.
- **Centrality** — emphasizes the most pivotal nodes.

### Importance encoding

The graph encodes analysis directly into the visuals:

- **Node size ∝ betweenness centrality** — pivotal "chokepoint" nodes (compromising them unlocks the most attack paths) appear larger.
- **Severity** — vulnerability nodes are colored/bordered by severity.
- **Dangerous capabilities** carry a distinct marker.
- **Attack-relevant edges** (`exploits`, `can_chain_to`, `leads_to`) are weighted and directional so attack flow stands out.

### Filtering

The **legend doubles as a filter** — toggle node types, edge types, and severity bands on/off. Text search and attack-path highlighting are also available. When a filter combination hides everything, a "nothing matches" state offers a one-click reset.

### Drill-down

- **Clustering** — collapse the graph into labeled super-nodes by **phase**, **type**, or **agent**, and expand on demand. Large graphs auto-cluster on first render so they open as a navigable overview instead of a hairball.
- **Attack-chain walker** — select a discovered attack path and step through it node-by-node with the current step focused and its context highlighted.
- **Cross-linking** — clicking a graph node scrolls to its attack-log entry (and OWASP/ATLAS mapping); activating an attack-log row focuses the matching node.
- **Multi-agent topology** — delegation, trust-boundary, and context-sharing edges render distinctly, and agents can be grouped into clusters.

### Timeline scrubber

For runs with per-phase snapshots, a **phase timeline scrubber** steps the graph through each phase so you can watch the campaign *grow* — nodes and edges appear as they were discovered. Older runs without per-phase snapshots fall back to showing the final end-state.

## Graph API

```python
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

graph = AttackKnowledgeGraph()

# Add nodes
graph.add_tool("read_file", {"description": "Read local files"})
graph.add_tool("http_request", {"description": "Make HTTP requests"})

# Add edges
graph.add_tool_chain(["read_file", "http_request"], risk_score=0.9)

# Find attack paths
paths = graph.find_all_attack_paths()

# Get critical nodes
critical = graph.get_critical_nodes(top_n=5)

# Export for visualization
state = graph.export_state()
```
