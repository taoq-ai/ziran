# Python API Reference

## Core Classes

### AgentScanner

The main campaign orchestrator.

```python
from koan.application.agent_scanner.scanner import AgentScanner

scanner = AgentScanner(
    adapter=my_adapter,
    attack_library=AttackLibrary(),
    custom_attacks_dir=Path("./my_attacks"),
    config={"key": "value"},
)

result = await scanner.run_campaign(
    phases=[ScanPhase.RECONNAISSANCE, ScanPhase.TRUST_BUILDING],
    stop_on_critical=True,
    reset_between_phases=False,
    on_progress=my_callback,
)
```

### AttackLibrary

Manages attack vectors.

```python
from koan.application.attacks.library import AttackLibrary

lib = AttackLibrary(custom_dirs=[Path("./my_attacks")])
vectors = lib.get_attacks_for_phase(ScanPhase.RECONNAISSANCE)
```

### AttackKnowledgeGraph

NetworkX-based knowledge graph.

```python
from koan.application.knowledge_graph.graph import AttackKnowledgeGraph

graph = AttackKnowledgeGraph()
graph.add_tool("read_file", {"description": "Read files"})
graph.add_tool_chain(["read_file", "http_request"], risk_score=0.9)
paths = graph.find_all_attack_paths()
state = graph.export_state()
```

### ToolChainAnalyzer

Analyzes knowledge graphs for dangerous tool chains.

```python
from koan.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer

analyzer = ToolChainAnalyzer(graph)
chains = analyzer.analyze()
```

### SkillCVEDatabase

Known vulnerabilities in agent tools.

```python
from koan.application.skill_cve import SkillCVEDatabase

db = SkillCVEDatabase()
matches = db.check_agent(capabilities)
```

## Data Models

### CampaignResult

Complete campaign result with all findings.

Key fields:
- `campaign_id: str`
- `total_vulnerabilities: int`
- `critical_paths: list[list[str]]`
- `dangerous_tool_chains: list[dict]`
- `critical_chain_count: int`
- `phases_executed: list[PhaseResult]`
- `final_trust_score: float`

### DangerousChain

A dangerous tool combination.

Key fields:
- `tools: list[str]` — Tool names in sequence
- `risk_level: str` — critical, high, medium, low
- `vulnerability_type: str`
- `exploit_description: str`
- `remediation: str`
- `risk_score: float` — 0.0–1.0

### AgentCapability

A discovered agent capability.

Key fields:
- `id: str`
- `name: str`
- `type: CapabilityType`
- `dangerous: bool`
- `requires_permission: bool`
