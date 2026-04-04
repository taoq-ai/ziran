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

## Visualization

The knowledge graph is rendered interactively in HTML reports using vis-network, with color-coded nodes and edges. Dangerous tool chains are highlighted in red.

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
