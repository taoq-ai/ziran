# Framework Adapters

KOAN uses adapters to communicate with different agent frameworks. This guide explains how to use built-in adapters and create custom ones.

## Built-in Adapters

### LangChain

```python
from koan.infrastructure.adapters.langchain_adapter import LangChainAdapter

adapter = LangChainAdapter(agent_executor=your_agent_executor)
```

Requires: `uv sync --extra langchain`

### CrewAI

```python
from koan.infrastructure.adapters.crewai_adapter import CrewAIAdapter

adapter = CrewAIAdapter(crew=your_crew)
```

Requires: `uv sync --extra crewai`

## Creating a Custom Adapter

Implement the `BaseAgentAdapter` abstract class:

```python
from koan.domain.interfaces.adapter import BaseAgentAdapter, AgentResponse, AgentState
from koan.domain.entities.capability import AgentCapability, CapabilityType

class MyAdapter(BaseAgentAdapter):
    def __init__(self, my_agent):
        self.agent = my_agent

    async def invoke(self, message: str, **kwargs) -> AgentResponse:
        """Send a message and get a response."""
        result = await self.agent.run(message)
        return AgentResponse(
            content=result.text,
            tool_calls=result.get_tool_calls(),
            metadata={"framework": "my_framework"},
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """List the agent's tools and capabilities."""
        tools = self.agent.get_tools()
        return [
            AgentCapability(
                id=f"tool_{t.name}",
                name=t.name,
                type=CapabilityType.TOOL,
                description=t.description,
                dangerous=t.name in ["shell_execute", "eval"],
            )
            for t in tools
        ]

    def get_state(self) -> AgentState:
        """Get current conversation state."""
        return AgentState(
            session_id="my-session",
            conversation_history=self.agent.get_history(),
        )

    def reset_state(self) -> None:
        """Reset conversation state."""
        self.agent.clear_history()
```

### Tips

- Mark dangerous tools in `discover_capabilities()` — this improves knowledge graph analysis
- Include `tool_calls` in `AgentResponse` when possible — KOAN uses this for detection
- Implement `observe_tool_call()` if your framework supports tool call hooks
