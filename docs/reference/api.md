# Python API Reference

## Scanning

### AgentScanner

The main campaign orchestrator.

```python
from ziran.application.agent_scanner.scanner import AgentScanner

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
from ziran.application.attacks.library import AttackLibrary

lib = AttackLibrary(custom_dirs=[Path("./my_attacks")])
vectors = lib.get_attacks_for_phase(ScanPhase.RECONNAISSANCE)
```

## Adapters

### LangChainAdapter

```python
from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter

adapter = LangChainAdapter(agent_executor=your_agent)
```

### CrewAIAdapter

```python
from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter

adapter = CrewAIAdapter(crew=your_crew)
```

### BedrockAdapter

```python
from ziran.infrastructure.adapters.bedrock_adapter import BedrockAdapter

adapter = BedrockAdapter(agent=your_bedrock_agent)
```

### HttpAgentAdapter (Remote Scanning)

```python
from ziran.infrastructure.adapters.http_agent_adapter import HttpAgentAdapter
from ziran.domain.entities.target import TargetConfig

config = TargetConfig.from_yaml("target.yaml")
adapter = HttpAgentAdapter(config)
```

### Custom Adapter

```python
from ziran.domain.interfaces.adapter import AgentAdapter, AgentResponse

class MyAdapter(AgentAdapter):
    async def send_message(self, message: str) -> AgentResponse:
        result = await my_agent.process(message)
        return AgentResponse(content=result)

    async def get_tools(self) -> list[ToolInfo]:
        return [...]

    async def reset_session(self) -> None:
        self.agent.clear_memory()
```

## Knowledge Graph

### AttackKnowledgeGraph

NetworkX-based knowledge graph.

```python
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

graph = AttackKnowledgeGraph()
graph.add_tool("read_file", {"description": "Read files"})
graph.add_tool_chain(["read_file", "http_request"], risk_score=0.9)
paths = graph.find_all_attack_paths()
critical = graph.get_critical_nodes(top_n=5)
state = graph.export_state()
```

### ToolChainAnalyzer

Analyzes knowledge graphs for dangerous tool chains.

```python
from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer

analyzer = ToolChainAnalyzer(graph)
chains = analyzer.analyze()

for chain in chains:
    print(f"{chain.risk_level}: {' → '.join(chain.tools)}")
    print(f"  Remediation: {chain.remediation}")
```

## Static Analysis

### StaticAnalyzer

```python
from ziran.application.static_analysis.analyzer import StaticAnalyzer
from ziran.application.static_analysis.config import StaticAnalysisConfig

# Default checks (SA001–SA010)
analyzer = StaticAnalyzer()
findings = analyzer.analyze_file("my_agent.py")
findings = analyzer.analyze_directory("./src/")

# Custom config
config = StaticAnalysisConfig.from_yaml("config.yaml")
analyzer = StaticAnalyzer(config=config)
```

## Dynamic Vector Generation

### DynamicVectorGenerator

LLM-powered generation of context-specific attack vectors.

```python
from ziran.application.dynamic_vectors.generator import DynamicVectorGenerator

generator = DynamicVectorGenerator()
vectors = await generator.generate(
    agent_capabilities=discovered_capabilities,
    existing_vectors=library.get_all_vectors(),
)
```

## PoC Generation

### PoCGenerator

Generates proof-of-concept exploits from findings.

```python
from ziran.application.poc_generator.generator import PoCGenerator

poc_gen = PoCGenerator()
pocs = poc_gen.generate(campaign_result, format="python")
poc_gen.save(pocs, output_dir=Path("./pocs"))
```

## Policy & CI/CD

### PolicyEngine

```python
from ziran.application.policy.engine import PolicyEngine
from ziran.domain.entities.policy import Policy

policy = Policy.from_yaml("policy.yaml")
engine = PolicyEngine()
verdict = engine.evaluate(campaign_result, policy)

print(f"Passed: {verdict.passed}")
for violation in verdict.violations:
    print(f"  {violation.rule_type}: {violation.message}")
```

### QualityGate

```python
from ziran.application.cicd.gate import QualityGate
from ziran.domain.entities.ci import QualityGateConfig

config = QualityGateConfig(
    min_trust_score=0.7,
    max_critical_findings=0,
    severity_thresholds=SeverityThresholds(critical=0, high=5),
)

gate = QualityGate()
gate_result = gate.evaluate(campaign_result, config)

print(f"Status: {gate_result.status}")  # passed or failed
print(f"Exit code: {gate_result.exit_code}")
```

## Target Configuration

### TargetConfig

```python
from ziran.domain.entities.target import (
    TargetConfig,
    ProtocolType,
    AuthType,
    AuthConfig,
    TlsConfig,
    RetryConfig,
    RestConfig,
    A2AConfig,
)

config = TargetConfig(
    url="https://agent.example.com",
    protocol=ProtocolType.OPENAI,
    auth=AuthConfig(type=AuthType.BEARER, token_env="API_KEY"),
    tls=TlsConfig(verify=True),
    retry=RetryConfig(max_retries=3),
    timeout=30,
)

# Or load from YAML
config = TargetConfig.from_yaml("target.yaml")
```

## Skill CVE Database

### SkillCVEDatabase

Known vulnerabilities in agent tools.

```python
from ziran.application.skill_cve import SkillCVEDatabase

db = SkillCVEDatabase()
matches = db.check_agent(capabilities)
```

## Data Models

### CampaignResult

Complete campaign result with all findings.

| Field | Type | Description |
|-------|------|-------------|
| `campaign_id` | `str` | Unique campaign identifier |
| `total_vulnerabilities` | `int` | Total findings count |
| `critical_paths` | `list[list[str]]` | Critical tool chain paths |
| `dangerous_tool_chains` | `list[dict]` | Dangerous chain details |
| `critical_chain_count` | `int` | Number of critical chains |
| `phases_executed` | `list[PhaseResult]` | Per-phase results |
| `final_trust_score` | `float` | Overall trust score (0.0–1.0) |

### DangerousChain

| Field | Type | Description |
|-------|------|-------------|
| `tools` | `list[str]` | Tool names in sequence |
| `risk_level` | `str` | `critical`, `high`, `medium`, `low` |
| `vulnerability_type` | `str` | Category of vulnerability |
| `exploit_description` | `str` | How the chain can be exploited |
| `remediation` | `str` | Suggested fix |
| `risk_score` | `float` | 0.0–1.0 |

### DetectorResult

| Field | Type | Description |
|-------|------|-------------|
| `detector_name` | `str` | Which detector produced this |
| `verdict` | `str` | `attack_success`, `attack_failure`, `uncertain` |
| `confidence` | `float` | 0.0–1.0 |
| `evidence` | `str` | What triggered the verdict |

### PolicyVerdict

| Field | Type | Description |
|-------|------|-------------|
| `passed` | `bool` | Whether all rules passed |
| `violations` | `list[PolicyViolation]` | Failed rules |
| `warnings` | `list[str]` | Non-blocking warnings |
| `summary` | `str` | Human-readable summary |

### GateResult

| Field | Type | Description |
|-------|------|-------------|
| `status` | `GateStatus` | `passed` or `failed` |
| `violations` | `list[GateViolation]` | Failed threshold checks |
| `trust_score` | `float` | Campaign trust score |
| `exit_code` | `int` | 0 = pass, 1 = fail |

### AgentCapability

A discovered agent capability.

Key fields:
- `id: str`
- `name: str`
- `type: CapabilityType`
- `dangerous: bool`
- `requires_permission: bool`
