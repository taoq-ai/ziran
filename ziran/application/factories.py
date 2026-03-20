"""Shared factories for adapter and strategy creation.

This module provides framework-agnostic factory functions for creating
agent adapters and campaign strategies. It is the single source of truth
for adapter/strategy instantiation, used by both the CLI and web UI.

All functions raise standard Python exceptions (``ValueError``,
``ImportError``, ``FileNotFoundError``) instead of framework-specific
ones so that any interface layer can catch and convert them.
"""

from __future__ import annotations

import contextlib
import importlib.util
import logging
import sys
from pathlib import Path
from typing import Any

from ziran.domain.entities.target import (
    ProtocolType,
    TargetConfig,
    TargetConfigError,
    load_target_config,
)

__all__ = [
    "build_strategy",
    "load_agent_adapter",
    "load_remote_adapter",
]

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Private helpers
# ──────────────────────────────────────────────────────────────────────


def _load_python_object(filepath: str, object_name: str) -> Any:
    """Load a Python object from a file by executing it.

    Executes the file and extracts the named object from its namespace.

    Args:
        filepath: Path to the Python file.
        object_name: Name of the object to extract.

    Returns:
        The extracted Python object.

    Raises:
        FileNotFoundError: If the file does not exist.
        ImportError: If the module cannot be loaded or executed.
        ValueError: If the named object is not found in the module.
    """
    path = Path(filepath).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    spec = importlib.util.spec_from_file_location("_ziran_target", str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load module from: {filepath}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["_ziran_target"] = module

    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise ImportError(f"Error executing {filepath}: {e}") from e

    obj = getattr(module, object_name, None)
    if obj is None:
        available = [a for a in dir(module) if not a.startswith("_")]
        raise ValueError(
            f"Object '{object_name}' not found in {filepath}. "
            f"Available objects: {', '.join(available)}"
        )

    return obj


def _load_bedrock_config(agent_path: str) -> dict[str, Any]:
    """Load Bedrock agent configuration from a YAML file or agent ID string.

    If ``agent_path`` ends with ``.yaml`` or ``.yml``, it's read as a
    YAML config with keys ``agent_id``, ``agent_alias_id``,
    ``region_name``, etc.  Otherwise it's treated as a bare agent ID.

    Args:
        agent_path: Path to YAML config or a Bedrock agent ID.

    Returns:
        Dict of kwargs for ``BedrockAdapter.__init__``.

    Raises:
        FileNotFoundError: If the YAML config file does not exist.
        ValueError: If the YAML is invalid or missing required keys.
    """
    if agent_path.endswith((".yaml", ".yml")):
        import yaml

        path = Path(agent_path)
        if not path.exists():
            raise FileNotFoundError(f"Bedrock config file not found: {agent_path}")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in Bedrock config: {exc}") from exc
        if not isinstance(data, dict) or "agent_id" not in data:
            raise ValueError("Bedrock config YAML must contain at least 'agent_id'")
        return data
    else:
        return {"agent_id": agent_path}


# ──────────────────────────────────────────────────────────────────────
# Public factory functions
# ──────────────────────────────────────────────────────────────────────


def load_remote_adapter(
    target_path: str,
    protocol_override: str | None = None,
) -> tuple[Any, TargetConfig]:
    """Create a remote agent adapter from a YAML target config.

    Creates either a :class:`BrowserAgentAdapter` (for ``protocol: browser``)
    or a :class:`HttpAgentAdapter` (for all other protocols).

    Args:
        target_path: Path to the YAML target configuration file.
        protocol_override: Optional protocol to override the config value.

    Returns:
        A tuple of ``(adapter, config)`` where *adapter* is a configured
        :class:`BaseAgentAdapter` instance and *config* is the loaded
        :class:`TargetConfig`.

    Raises:
        FileNotFoundError: If the target config file does not exist.
        ValueError: If the config is invalid.
        ImportError: If required dependencies are not installed.
    """
    try:
        config = load_target_config(Path(target_path))
    except (FileNotFoundError, ValueError):
        raise
    except TargetConfigError as e:
        # TargetConfigError may wrap file-not-found or validation errors
        msg = str(e)
        if "not found" in msg.lower():
            raise FileNotFoundError(msg) from e
        raise ValueError(msg) from e
    except Exception as e:
        raise ValueError(f"Unexpected error loading target config from {target_path}: {e}") from e

    if protocol_override:
        config.protocol = ProtocolType(protocol_override)

    if config.protocol == ProtocolType.BROWSER:
        try:
            from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter
        except ImportError as e:
            raise ImportError(
                "Playwright is required for browser scanning. "
                "Install with: pip install ziran[browser] && playwright install chromium\n"
                f"{e}"
            ) from e
        return BrowserAgentAdapter(config), config

    from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

    return HttpAgentAdapter(config), config


def load_agent_adapter(framework: str, agent_path: str) -> Any:
    """Create an agent adapter for the specified framework.

    Dynamically imports the adapter module to keep framework
    dependencies optional (lazy loading).

    Args:
        framework: Framework name (``langchain``, ``crewai``, ``bedrock``,
            ``agentcore``).
        agent_path: Path to the agent code/config.

    Returns:
        Configured :class:`BaseAgentAdapter` instance.

    Raises:
        ValueError: If the framework is not supported.
        ImportError: If the framework's dependencies are not installed.
        FileNotFoundError: If the agent file does not exist.
    """
    if framework == "langchain":
        try:
            from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter
        except ImportError as e:
            raise ImportError(
                f"LangChain not installed. Run: uv sync --extra langchain\n{e}"
            ) from e

        agent_executor = _load_python_object(agent_path, "agent_executor")
        return LangChainAdapter(agent_executor)

    if framework == "crewai":
        try:
            from ziran.infrastructure.adapters.crewai_adapter import CrewAIAdapter
        except ImportError as e:
            raise ImportError(f"CrewAI not installed. Run: uv sync --extra crewai\n{e}") from e

        crew = _load_python_object(agent_path, "crew")
        return CrewAIAdapter(crew)

    if framework == "bedrock":
        try:
            from ziran.infrastructure.adapters.bedrock_adapter import BedrockAdapter
        except ImportError as e:
            raise ImportError(f"boto3 not installed. Run: uv sync --extra bedrock\n{e}") from e

        bedrock_config = _load_bedrock_config(agent_path)
        return BedrockAdapter(**bedrock_config)

    if framework == "agentcore":
        try:
            from ziran.infrastructure.adapters.agentcore_adapter import AgentCoreAdapter
        except ImportError as e:
            raise ImportError(
                f"bedrock-agentcore not installed. Run: uv sync --extra agentcore\n{e}"
            ) from e

        entrypoint = _load_python_object(agent_path, "invoke")
        # Try to also load the app object for capability discovery
        app = None
        with contextlib.suppress(FileNotFoundError, ImportError, ValueError):
            app = _load_python_object(agent_path, "app")
        return AgentCoreAdapter(entrypoint, app=app)

    raise ValueError(f"Unsupported framework: {framework}")


def build_strategy(
    strategy_name: str,
    stop_on_critical: bool,
    llm_client: Any | None = None,
) -> Any:
    """Build a campaign strategy from its name.

    Args:
        strategy_name: One of ``'fixed'``, ``'adaptive'``, ``'llm-adaptive'``.
        stop_on_critical: Whether to stop on critical findings.
        llm_client: LLM client instance (required for ``'llm-adaptive'``).

    Returns:
        A :class:`CampaignStrategy` instance.
    """
    from ziran.application.strategies.adaptive import AdaptiveStrategy
    from ziran.application.strategies.fixed import FixedStrategy

    if strategy_name == "adaptive":
        return AdaptiveStrategy(stop_on_critical=stop_on_critical)

    if strategy_name == "llm-adaptive":
        if llm_client is None:
            logger.warning(
                "llm-adaptive strategy requires --llm-provider/--llm-model. "
                "Falling back to adaptive strategy."
            )
            return AdaptiveStrategy(stop_on_critical=stop_on_critical)
        from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy

        return LLMAdaptiveStrategy(
            llm_client=llm_client,
            stop_on_critical=stop_on_critical,
        )

    # Default: fixed
    return FixedStrategy(stop_on_critical=stop_on_critical)
