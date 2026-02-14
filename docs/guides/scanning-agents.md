# Scanning Agents

This guide covers how to scan agents across different frameworks — both local and remote.

## Local Agents

### LangChain

```bash
ziran scan --framework langchain --agent-path my_agent.py
```

Your agent file should export an `agent_executor` object:

```python
# my_agent.py
from langchain.agents import AgentExecutor

agent_executor = AgentExecutor(agent=agent, tools=tools)
```

### CrewAI

```bash
ziran scan --framework crewai --agent-path my_crew.py
```

Your file should export a `crew` object:

```python
# my_crew.py
from crewai import Crew

crew = Crew(agents=[...], tasks=[...])
```

### Amazon Bedrock

```bash
ziran scan --framework bedrock --agent-path my_bedrock_agent.py
```

### Custom Framework

Implement `AgentAdapter` for any framework:

```python
from ziran.domain.interfaces.adapter import AgentAdapter, AgentResponse

class MyAdapter(AgentAdapter):
    async def send_message(self, message: str) -> AgentResponse:
        result = await my_agent.process(message)
        return AgentResponse(content=result)

    async def get_tools(self) -> list[ToolInfo]:
        return [...]  # Discovered tools

    async def reset_session(self) -> None:
        self.agent.clear_memory()
```

Then use the Python API:

```python
scanner = AgentScanner(adapter=MyAdapter(), attack_library=AttackLibrary())
result = await scanner.run_campaign()
```

## Remote Agents

Scan any agent published over HTTPS — no source code required:

```bash
# Create a target config
cat > target.yaml << 'EOF'
name: "My Agent"
url: "https://my-agent.example.com"
protocol: auto
auth:
  type: bearer
  token_env: MY_API_KEY
EOF

# Scan it
ziran scan --target target.yaml
```

See [Remote Agent Scanning Guide](remote-agents.md) for protocol-specific configuration.

## Scan Options

### Coverage Level

```bash
# Quick check (phases 1-4)
ziran scan --target target.yaml --coverage essential

# Standard (phases 1-6, default)
ziran scan --target target.yaml --coverage standard

# Full audit (all 8 phases)
ziran scan --target target.yaml --coverage comprehensive
```

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

### Concurrency

```bash
# Run up to 10 attacks in parallel
ziran scan --target target.yaml --concurrency 10
```

### Custom Attack Vectors

```bash
ziran scan --framework langchain --agent-path agent.py --custom-attacks ./my_attacks/
```

### Output Directory

```bash
ziran scan --framework langchain --agent-path agent.py --output ./my_results/
```

## Report Formats

After a scan, generate reports in different formats:

```bash
# Terminal summary (default)
ziran report results.json

# HTML with interactive knowledge graph
ziran report results.json --format html

# Markdown for code reviews
ziran report results.json --format markdown

# JSON for programmatic use
ziran report results.json --format json
```
