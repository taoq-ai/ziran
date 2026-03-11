"""Promptfoo custom provider for ZIRAN security analysis.

Exposes ZIRAN as a Promptfoo provider so security tests can be run
via Promptfoo's configuration-driven evaluation framework.

Promptfoo calls ``call_api(prompt, options, context)`` for each test
case. The provider creates an adapter targeting the configured agent,
runs a single-prompt analysis or full campaign, and returns results
in Promptfoo's expected format.

Usage in promptfooconfig.yaml::

    providers:
      - id: python:ziran.integrations.promptfoo.provider
        config:
          target_url: http://localhost:8000/chat
          protocol: openai
          # Optional: run full campaign instead of single prompt
          # full_campaign: true

See: https://www.promptfoo.dev/docs/providers/custom-api/
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


def call_api(
    prompt: str,
    options: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Promptfoo provider entry point.

    Called by Promptfoo for each test case. Runs ZIRAN analysis
    against the configured target agent.

    Args:
        prompt: The prompt text from the test case.
        options: Provider config from promptfooconfig.yaml.
        context: Promptfoo context (vars, test metadata).

    Returns:
        Dict with ``output``, ``tokenUsage``, and ``metadata`` keys.
    """
    options = options or {}
    context = context or {}
    config = options.get("config", {})

    target_url = config.get("target_url", "")
    if not target_url:
        return {
            "output": "Error: 'target_url' is required in provider config",
            "error": "Missing target_url in config",
        }

    try:
        return asyncio.run(_run_analysis(prompt, config, context))
    except Exception as exc:
        logger.exception("ZIRAN provider error")
        return {
            "output": f"Error: {exc}",
            "error": str(exc),
        }


async def _run_analysis(
    prompt: str,
    config: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    """Run ZIRAN analysis asynchronously.

    Creates an HttpAgentAdapter and either runs a single prompt
    or a full campaign depending on configuration.
    """
    from ziran.domain.entities.target import TargetConfig
    from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

    target_config = TargetConfig(
        url=config["target_url"],
        protocol=config.get("protocol", "auto"),
    )
    adapter = HttpAgentAdapter(target_config)

    if config.get("full_campaign", False):
        return await _run_campaign(adapter, config)

    return await _run_single_prompt(adapter, prompt, config)


async def _run_single_prompt(
    adapter: Any,
    prompt: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Send a single prompt and return the response with metadata."""
    response = await adapter.invoke(prompt)

    # Basic vulnerability signals
    metadata: dict[str, Any] = {
        "tool_calls": response.tool_calls,
        "tool_call_count": len(response.tool_calls),
        "has_tool_calls": bool(response.tool_calls),
    }

    # Run indicator-based detection if success_indicators provided
    indicators = config.get("success_indicators", [])
    if indicators and response.content:
        content_lower = response.content.lower()
        matched = [ind for ind in indicators if ind.lower() in content_lower]
        metadata["matched_indicators"] = matched
        metadata["indicator_match_rate"] = len(matched) / len(indicators) if indicators else 0

    return {
        "output": response.content or "",
        "tokenUsage": {
            "total": response.total_tokens,
            "prompt": response.prompt_tokens,
            "completion": response.completion_tokens,
        },
        "metadata": metadata,
    }


async def _run_campaign(
    adapter: Any,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Run a full ZIRAN campaign and return aggregated results."""
    from ziran.application.agent_scanner.scanner import AgentScanner
    from ziran.application.attacks.library import AttackLibrary

    library = AttackLibrary()
    scanner = AgentScanner(adapter=adapter, attack_library=library)

    campaign = await scanner.run_campaign()

    vulnerabilities = []
    for result_dict in campaign.attack_results:
        if result_dict.get("successful"):
            vulnerabilities.append(
                {
                    "vector_id": result_dict.get("vector_id"),
                    "vector_name": result_dict.get("vector_name"),
                    "category": result_dict.get("category"),
                    "severity": result_dict.get("severity"),
                }
            )

    total_tokens = campaign.token_usage.get("total_tokens", 0)

    return {
        "output": (
            f"ZIRAN scan complete: {campaign.total_vulnerabilities} vulnerabilities found, "
            f"trust score {campaign.final_trust_score:.2f}"
        ),
        "tokenUsage": {
            "total": total_tokens,
            "prompt": 0,
            "completion": 0,
        },
        "metadata": {
            "campaign_id": campaign.campaign_id,
            "total_vulnerabilities": campaign.total_vulnerabilities,
            "trust_score": campaign.final_trust_score,
            "vulnerabilities": vulnerabilities,
            "dangerous_chains": campaign.dangerous_tool_chains,
            "critical_paths": campaign.critical_paths,
        },
    }
