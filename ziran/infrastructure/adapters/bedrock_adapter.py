"""AWS Bedrock Agents adapter.

Wraps AWS Bedrock Agents via ``boto3`` to implement the ZIRAN
BaseAgentAdapter interface. Sends messages via ``invoke_agent`` and
discovers capabilities through the Bedrock Agent management API.

Requires the ``bedrock`` extra::

    uv sync --extra bedrock
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from ziran.domain.entities.capability import AgentCapability, CapabilityType
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter

logger = logging.getLogger(__name__)


def _import_boto3() -> Any:
    """Lazy-import boto3 and return the module."""
    try:
        import boto3

        return boto3
    except ImportError as e:
        raise ImportError(
            "boto3 is required for BedrockAdapter. Install it with: uv sync --extra bedrock"
        ) from e


class BedrockAdapter(BaseAgentAdapter):
    """Adapter for AWS Bedrock Agents.

    Uses ``bedrock-agent-runtime`` to invoke agents and
    ``bedrock-agent`` to discover their capabilities (action groups,
    knowledge bases).

    Example:
        ```python
        from ziran.infrastructure.adapters.bedrock_adapter import BedrockAdapter

        adapter = BedrockAdapter(
            agent_id="ABCDE12345",
            agent_alias_id="TSTALIASID",
            region_name="us-east-1",
        )
        response = await adapter.invoke("What can you do?")
        ```
    """

    def __init__(
        self,
        agent_id: str,
        agent_alias_id: str = "TSTALIASID",
        region_name: str = "us-east-1",
        **kwargs: Any,
    ) -> None:
        """Initialize with a Bedrock agent ID.

        Args:
            agent_id: The AWS Bedrock agent ID.
            agent_alias_id: The agent alias ID (default: test alias).
            region_name: AWS region where the agent is deployed.
            **kwargs: Additional boto3 session configuration
                      (profile_name, aws_access_key_id, etc.).
        """
        boto3 = _import_boto3()

        session_kwargs: dict[str, Any] = {"region_name": region_name}
        session_kwargs.update(kwargs)
        session = boto3.Session(**session_kwargs)

        self._runtime_client = session.client("bedrock-agent-runtime")
        self._mgmt_client = session.client("bedrock-agent")
        self.agent_id = agent_id
        self.agent_alias_id = agent_alias_id
        self._session_id: str = str(uuid.uuid4())
        self._conversation_history: list[dict[str, str]] = []
        self._observed_tool_calls: list[dict[str, Any]] = []

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        """Send a message to the Bedrock agent.

        Runs the synchronous ``invoke_agent`` call in a thread to
        maintain async contract.

        Args:
            message: The user prompt.
            **kwargs: Additional parameters passed to ``invoke_agent``.

        Returns:
            Standardized agent response.
        """
        result = await asyncio.to_thread(self._invoke_sync, message, **kwargs)
        return result

    def _invoke_sync(self, message: str, **kwargs: Any) -> AgentResponse:
        """Synchronous invoke_agent call."""
        response = self._runtime_client.invoke_agent(
            agentId=self.agent_id,
            agentAliasId=self.agent_alias_id,
            sessionId=self._session_id,
            inputText=message,
            **kwargs,
        )

        # Parse streaming completion chunks
        completion_text = ""
        tool_calls: list[dict[str, Any]] = []

        for event in response.get("completion", []):
            chunk = event.get("chunk", {})
            if "bytes" in chunk:
                completion_text += chunk["bytes"].decode("utf-8")

            # Parse trace events for tool calls
            trace = event.get("trace", {})
            orchestration_trace = trace.get("trace", {}).get("orchestrationTrace", {})
            invocation_input = orchestration_trace.get("invocationInput", {})

            if "actionGroupInvocationInput" in invocation_input:
                ag = invocation_input["actionGroupInvocationInput"]
                tool_calls.append(
                    {
                        "tool": ag.get("actionGroupName", "unknown"),
                        "input": {
                            "function": ag.get("function", ""),
                            "parameters": ag.get("parameters", []),
                            "api_path": ag.get("apiPath", ""),
                        },
                        "output": "",
                    }
                )
                self._observed_tool_calls.append(tool_calls[-1])

        self._conversation_history.append({"role": "user", "content": message})
        self._conversation_history.append({"role": "assistant", "content": completion_text})

        return AgentResponse(
            content=completion_text,
            tool_calls=tool_calls,
            metadata={
                "agent_id": self.agent_id,
                "session_id": self._session_id,
                "protocol": "bedrock-agent",
            },
        )

    async def discover_capabilities(self) -> list[AgentCapability]:
        """Discover Bedrock agent capabilities.

        Queries the management API for action groups and knowledge
        bases associated with the agent.

        Returns:
            List of discovered capabilities.
        """
        capabilities: list[AgentCapability] = []

        try:
            ag_response = await asyncio.to_thread(
                self._mgmt_client.list_agent_action_groups,
                agentId=self.agent_id,
                agentVersion="DRAFT",
            )

            for ag in ag_response.get("actionGroupSummaries", []):
                capabilities.append(
                    AgentCapability(
                        id=f"bedrock_ag_{ag.get('actionGroupId', 'unknown')}",
                        name=ag.get("actionGroupName", "unknown"),
                        type=CapabilityType.TOOL,
                        description=ag.get("description"),
                        parameters={},
                        dangerous=_is_dangerous_action_group(ag.get("actionGroupName", "")),
                    )
                )
        except Exception:
            logger.warning("Failed to list Bedrock agent action groups")

        try:
            kb_response = await asyncio.to_thread(
                self._mgmt_client.list_agent_knowledge_bases,
                agentId=self.agent_id,
                agentVersion="DRAFT",
            )

            for kb in kb_response.get("agentKnowledgeBaseSummaries", []):
                capabilities.append(
                    AgentCapability(
                        id=f"bedrock_kb_{kb.get('knowledgeBaseId', 'unknown')}",
                        name=f"KB: {kb.get('description', kb.get('knowledgeBaseId', 'unknown'))}",
                        type=CapabilityType.DATA_ACCESS,
                        description=kb.get("description"),
                        parameters={},
                        dangerous=False,
                    )
                )
        except Exception:
            logger.warning("Failed to list Bedrock agent knowledge bases")

        logger.info(
            "Discovered %d Bedrock capabilities (%d dangerous)",
            len(capabilities),
            sum(1 for c in capabilities if c.dangerous),
        )
        return capabilities

    def get_state(self) -> AgentState:
        """Get current agent state snapshot.

        Returns:
            Agent state with conversation history and session info.
        """
        return AgentState(
            session_id=self._session_id,
            conversation_history=list(self._conversation_history),
            memory={"agent_id": self.agent_id, "alias_id": self.agent_alias_id},
        )

    def reset_state(self) -> None:
        """Reset agent to initial state.

        Creates a new session ID and clears conversation history.
        """
        self._session_id = str(uuid.uuid4())
        self._conversation_history.clear()
        self._observed_tool_calls.clear()

    def observe_tool_call(
        self,
        tool_name: str,
        inputs: dict[str, Any],
        outputs: Any,
    ) -> None:
        """Record an observed tool call.

        Args:
            tool_name: Name of the tool invoked.
            inputs: Input parameters.
            outputs: Tool output.
        """
        self._observed_tool_calls.append(
            {
                "tool": tool_name,
                "input": inputs,
                "output": str(outputs),
            }
        )


# Action group names that heuristically indicate dangerous capabilities
_DANGEROUS_KEYWORDS: frozenset[str] = frozenset(
    {
        "execute",
        "shell",
        "code",
        "file",
        "write",
        "delete",
        "database",
        "sql",
        "admin",
        "system",
        "lambda",
        "invoke",
    }
)


def _is_dangerous_action_group(name: str) -> bool:
    """Heuristic check for potentially dangerous action groups."""
    name_lower = name.lower()
    return any(keyword in name_lower for keyword in _DANGEROUS_KEYWORDS)
