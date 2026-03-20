"""Unit tests for shared factory functions in ziran.application.factories.

Tests cover all three public factories (load_remote_adapter,
load_agent_adapter, build_strategy), private helpers, import isolation,
and hexagonal architecture compliance.
"""

from __future__ import annotations

import ast
import logging
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ──────────────────────────────────────────────────────────────────────
# load_remote_adapter
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLoadRemoteAdapter:
    """Tests for load_remote_adapter factory."""

    def test_creates_http_adapter_from_yaml(self) -> None:
        from ziran.application.factories import load_remote_adapter

        yaml_content = "url: https://api.example.com\nprotocol: rest\n"

        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            adapter, config = load_remote_adapter(f.name)

        assert adapter.__class__.__name__ == "HttpAgentAdapter"
        assert config.url == "https://api.example.com"

    def test_creates_http_adapter_with_openai_protocol(self) -> None:
        from ziran.application.factories import load_remote_adapter

        yaml_content = "url: https://api.example.com\nprotocol: openai\n"

        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            adapter, _config = load_remote_adapter(f.name)

        assert adapter.__class__.__name__ == "HttpAgentAdapter"

    def test_protocol_override(self) -> None:
        from ziran.application.factories import load_remote_adapter

        yaml_content = "url: https://api.example.com\nprotocol: rest\n"

        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            _adapter, config = load_remote_adapter(f.name, protocol_override="openai")

        assert config.protocol.value == "openai"

    def test_missing_file_raises_file_not_found(self) -> None:
        from ziran.application.factories import load_remote_adapter

        with pytest.raises(FileNotFoundError):
            load_remote_adapter("/nonexistent/target.yaml")

    def test_returns_tuple_of_adapter_and_config(self) -> None:
        from ziran.application.factories import load_remote_adapter
        from ziran.domain.entities.target import TargetConfig

        yaml_content = "url: https://api.example.com\nprotocol: rest\n"

        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            result = load_remote_adapter(f.name)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[1], TargetConfig)


# ──────────────────────────────────────────────────────────────────────
# load_agent_adapter
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLoadAgentAdapter:
    """Tests for load_agent_adapter factory."""

    def test_langchain_adapter(self) -> None:
        from ziran.application.factories import load_agent_adapter

        with patch("ziran.application.factories._load_python_object") as mock_load:
            mock_load.return_value = MagicMock()
            adapter = load_agent_adapter("langchain", "/fake/path.py")
            assert adapter.__class__.__name__ == "LangChainAdapter"

    def test_crewai_adapter(self) -> None:
        from ziran.application.factories import load_agent_adapter

        with patch("ziran.application.factories._load_python_object") as mock_load:
            mock_load.return_value = MagicMock()
            adapter = load_agent_adapter("crewai", "/fake/path.py")
            assert adapter.__class__.__name__ == "CrewAIAdapter"

    def test_bedrock_adapter(self) -> None:
        from ziran.application.factories import load_agent_adapter

        with (
            patch("ziran.application.factories._load_bedrock_config") as mock_cfg,
        ):
            mock_cfg.return_value = {"agent_id": "test123", "region_name": "us-east-1"}
            try:
                adapter = load_agent_adapter("bedrock", "/fake/config.yaml")
                assert adapter.__class__.__name__ == "BedrockAdapter"
            except ImportError:
                pass  # boto3 may not be installed

    def test_agentcore_adapter(self) -> None:
        from ziran.application.factories import load_agent_adapter

        with patch("ziran.application.factories._load_python_object") as mock_load:
            mock_load.return_value = MagicMock()
            adapter = load_agent_adapter("agentcore", "/fake/path.py")
            assert adapter.__class__.__name__ == "AgentCoreAdapter"

    def test_unsupported_framework_raises_value_error(self) -> None:
        from ziran.application.factories import load_agent_adapter

        with pytest.raises(ValueError, match="Unsupported framework"):
            load_agent_adapter("unknown_fw", "/fake/path.py")


# ──────────────────────────────────────────────────────────────────────
# build_strategy
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestBuildStrategy:
    """Tests for build_strategy factory."""

    def test_fixed_strategy(self) -> None:
        from ziran.application.factories import build_strategy

        strategy = build_strategy("fixed", stop_on_critical=True)
        assert strategy.__class__.__name__ == "FixedStrategy"

    def test_adaptive_strategy(self) -> None:
        from ziran.application.factories import build_strategy

        strategy = build_strategy("adaptive", stop_on_critical=False)
        assert strategy.__class__.__name__ == "AdaptiveStrategy"

    def test_llm_adaptive_with_client(self) -> None:
        from ziran.application.factories import build_strategy

        mock_llm = MagicMock()
        strategy = build_strategy("llm-adaptive", stop_on_critical=True, llm_client=mock_llm)
        assert strategy.__class__.__name__ == "LLMAdaptiveStrategy"

    def test_llm_adaptive_without_client_falls_back(self) -> None:
        from ziran.application.factories import build_strategy

        strategy = build_strategy("llm-adaptive", stop_on_critical=False, llm_client=None)
        assert strategy.__class__.__name__ == "AdaptiveStrategy"

    def test_llm_adaptive_fallback_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        from ziran.application.factories import build_strategy

        with caplog.at_level(logging.WARNING, logger="ziran.application.factories"):
            build_strategy("llm-adaptive", stop_on_critical=True, llm_client=None)

        assert "Falling back to adaptive" in caplog.text

    def test_unknown_strategy_defaults_to_fixed(self) -> None:
        from ziran.application.factories import build_strategy

        strategy = build_strategy("unknown", stop_on_critical=True)
        assert strategy.__class__.__name__ == "FixedStrategy"


# ──────────────────────────────────────────────────────────────────────
# Import isolation (US2)
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestImportIsolation:
    """Verify factories module has no CLI/interface dependencies."""

    def test_no_click_or_rich_in_source(self) -> None:
        """Verify that the factories module source does not import click or rich."""
        factories_path = (
            Path(__file__).resolve().parents[3] / "ziran" / "application" / "factories.py"
        )
        source = factories_path.read_text()
        tree = ast.parse(source)

        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_names.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_names.add(node.module.split(".")[0])

        assert "click" not in imported_names, "factories.py must not import click"
        assert "rich" not in imported_names, "factories.py must not import rich"


# ──────────────────────────────────────────────────────────────────────
# Architecture compliance (US3)
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestArchitectureCompliance:
    """Verify factories module only depends on domain and infrastructure layers."""

    def test_no_interface_layer_imports(self) -> None:
        """Verify factories.py has zero imports from ziran.interfaces."""
        factories_path = (
            Path(__file__).resolve().parents[3] / "ziran" / "application" / "factories.py"
        )
        source = factories_path.read_text()
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("ziran.interfaces"), (
                    f"factories.py must not import from ziran.interfaces, "
                    f"found: from {node.module} import ..."
                )
