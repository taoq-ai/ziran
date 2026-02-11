# Scanning Agents

This guide covers how to scan agents across different frameworks.

## LangChain Agents

```bash
ziran scan --framework langchain --agent-path my_agent.py
```

Your agent file should export an `agent_executor` object:

```python
# my_agent.py
from langchain.agents import AgentExecutor

agent_executor = AgentExecutor(agent=agent, tools=tools)
```

## CrewAI Agents

```bash
ziran scan --framework crewai --agent-path my_crew.py
```

Your file should export a `crew` object:

```python
# my_crew.py
from crewai import Crew

crew = Crew(agents=[...], tasks=[...])
```

## Custom Agents

Implement `BaseAgentAdapter` for any framework:

```python
from ziran.domain.interfaces.adapter import BaseAgentAdapter, AgentResponse

class MyAdapter(BaseAgentAdapter):
    async def invoke(self, message: str, **kwargs) -> AgentResponse:
        result = await my_agent.process(message)
        return AgentResponse(content=result)
    
    async def discover_capabilities(self):
        return [...]  # List of AgentCapability objects
```

Then use the Python API:

```python
scanner = AgentScanner(adapter=MyAdapter(), attack_library=AttackLibrary())
result = await scanner.run_campaign()
```

## Scan Options

### Selecting Phases

```bash
# Run specific phases only
ziran scan --framework langchain --agent-path agent.py \
  --phases reconnaissance trust_building vulnerability_discovery
```

### Stop on Critical

```bash
# Stop campaign when a critical vulnerability is found (default)
ziran scan --framework langchain --agent-path agent.py --stop-on-critical

# Continue even after critical findings
ziran scan --framework langchain --agent-path agent.py --no-stop-on-critical
```

### Custom Attack Vectors

```bash
ziran scan --framework langchain --agent-path agent.py --custom-attacks ./my_attacks/
```

### Output Directory

```bash
ziran scan --framework langchain --agent-path agent.py --output ./my_results/
```
