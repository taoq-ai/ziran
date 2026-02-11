# Knowledge Graph

ZIRAN uses a **NetworkX-based directed multigraph** to track all discoveries, relationships, and attack paths during a scan campaign.

## Node Types

| Type | Shape | Description |
|------|-------|-------------|
| `capability` | Circle | A discovered agent capability |
| `tool` | Diamond | An invokable tool the agent has access to |
| `vulnerability` | Triangle | A discovered vulnerability |
| `data_source` | Square | A data source the agent can access |
| `phase` | Hexagon | A scan phase execution |
| `agent_state` | Ellipse | A snapshot of agent state |

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
