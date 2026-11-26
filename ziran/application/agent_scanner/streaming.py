"""Streamed target calls, accumulated into one :class:`AgentResponse` (from AttackExecutor)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ziran.application.agent_scanner.progress import ProgressEvent, ProgressEventType
from ziran.domain.interfaces.adapter import AgentResponse

if TYPE_CHECKING:
    from ziran.application.agent_scanner.progress import ProgressEmitter
    from ziran.domain.interfaces.adapter import BaseAgentAdapter


async def invoke_streaming(
    adapter: BaseAgentAdapter, emitter: ProgressEmitter, prompt: str, attack_name: str
) -> AgentResponse:
    """Invoke the agent with streaming and accumulate into AgentResponse."""
    content_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}

    async for chunk in adapter.stream(prompt):
        if chunk.content_delta:
            content_parts.append(chunk.content_delta)

        if chunk.tool_call_delta:
            tool_calls.append(chunk.tool_call_delta)

        # Emit streaming progress event
        emitter.emit(
            ProgressEvent(
                event=ProgressEventType.ATTACK_STREAMING,
                attack_name=attack_name,
                message=chunk.content_delta,
                extra={
                    "is_final": chunk.is_final,
                    "chunk_metadata": chunk.metadata,
                },
            )
        )

        if chunk.is_final:
            metadata = chunk.metadata

    content = "".join(content_parts)
    final_tool_calls = metadata.get("tool_calls", tool_calls)

    return AgentResponse(
        content=content,
        tool_calls=final_tool_calls,
        metadata=metadata,
        prompt_tokens=metadata.get("prompt_tokens", 0),
        completion_tokens=metadata.get("completion_tokens", 0),
        total_tokens=metadata.get("total_tokens", 0),
    )
