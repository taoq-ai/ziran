"""Internal LLM backbone — multi-vendor LLM client abstraction.

Provides a unified interface for calling LLMs from within ZIRAN
(e.g. LLM-as-a-judge, AI-powered mutation). This is separate from
the protocol handlers that send attack prompts *to* target agents.

Usage:
    from ziran.infrastructure.llm import create_llm_client

    client = create_llm_client(provider="anthropic", model="claude-sonnet-4-20250514")
    response = await client.complete([
        {"role": "system", "content": "You are a security analyst."},
        {"role": "user", "content": "Evaluate this response..."},
    ])
"""

from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse
from ziran.infrastructure.llm.factory import create_llm_client

__all__ = [
    "BaseLLMClient",
    "LLMConfig",
    "LLMResponse",
    "create_llm_client",
]
