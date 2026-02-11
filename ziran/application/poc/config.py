"""Configuration models for the PoC Generator.

All template strings, metadata labels, and formatting options are
expressed as Pydantic models backed by YAML so organisations can
customise the generated output without touching code.

Example::

    config = PoCConfig.default()
    custom = PoCConfig.from_yaml(Path("my_poc.yaml"))
    merged = config.merge(custom)
    generator = PoCGenerator(output_dir=out, config=merged)
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

# ── Building blocks ──────────────────────────────────────────────────


class PythonPoCTemplate(BaseModel):
    """Template settings for generated Python PoC scripts."""

    shebang: str = "#!/usr/bin/env python3"
    """Shebang line for the script."""

    imports: list[str] = Field(
        default_factory=lambda: ["asyncio", "sys"],
    )
    """Modules to import in the generated script."""

    run_instructions: list[str] = Field(
        default_factory=lambda: [
            "To reproduce, configure your agent adapter and call:",
            "  asyncio.run(reproduce(your_adapter))",
            "",
            "Example with LangChain:",
            "  from ziran.infrastructure.adapters.langchain_adapter import LangChainAdapter",
            "  adapter = LangChainAdapter(your_agent_executor)",
            "  asyncio.run(reproduce(adapter))",
        ],
    )
    """Lines printed when the PoC is executed directly."""

    vulnerable_text_match: str = "VULNERABLE — Matched indicators: {matched}"
    """Template for the success message when text indicators match."""

    vulnerable_tool_match: str = "VULNERABLE — Dangerous tool execution detected"
    """Message when tool calls are detected."""

    not_reproduced: str = "Not reproduced — no indicators matched"
    """Message when no indicators match."""


class CurlPoCTemplate(BaseModel):
    """Template settings for generated cURL PoC scripts."""

    default_endpoint: str = "http://localhost:8000/invoke"
    """Fallback endpoint when none is provided."""

    max_response_chars: int = 500
    """Number of response characters to display."""

    max_indicators: int = 5
    """Maximum indicators to check in the grep loop."""


class MarkdownGuideTemplate(BaseModel):
    """Template settings for the Markdown reproduction guide."""

    title: str = "ZIRAN Vulnerability Reproduction Guide"
    """Document title."""

    footer_link_text: str = "ZIRAN"
    """Display text for the footer link."""

    footer_link_url: str = "https://github.com/taoq-ai/ziran"
    """URL for the footer link."""

    footer_tagline: str = "AI Agent Security Testing Framework"
    """Tagline after the footer link."""

    max_response_snippet_chars: int = 500
    """Max chars for agent response code blocks."""


# ── Top-level config ─────────────────────────────────────────────────


class PoCConfig(BaseModel):
    """Full configuration for the PoC Generator.

    Controls template text, formatting options, and labelling
    for all three output formats (Python, cURL, Markdown).
    """

    generator_label: str = "ZIRAN AI Agent Security Testing Framework"
    """Attribution label embedded in generated artifacts."""

    python_template: PythonPoCTemplate = Field(
        default_factory=PythonPoCTemplate,
    )
    """Settings for Python PoC scripts."""

    curl_template: CurlPoCTemplate = Field(
        default_factory=CurlPoCTemplate,
    )
    """Settings for cURL PoC scripts."""

    markdown_template: MarkdownGuideTemplate = Field(
        default_factory=MarkdownGuideTemplate,
    )
    """Settings for Markdown reproduction guides."""

    # ── I/O ──────────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: Path) -> PoCConfig:
        """Load configuration from a YAML file."""
        if not path.exists():
            msg = f"Config file not found: {path}"
            raise FileNotFoundError(msg)

        with path.open() as fh:
            data = yaml.safe_load(fh)

        if not isinstance(data, dict):
            msg = f"Invalid config — expected mapping, got {type(data).__name__}"
            raise ValueError(msg)

        return cls.model_validate(data)

    @classmethod
    def default(cls) -> PoCConfig:
        """Load the built-in default configuration."""
        default_path = Path(__file__).parent / "default_config.yaml"
        return cls.from_yaml(default_path)

    # ── Merge ────────────────────────────────────────────────────────

    def merge(self, other: PoCConfig) -> PoCConfig:
        """Merge *other* config into this one.

        Scalar fields from *other* replace those in *self* when
        they differ from the class default.  List fields are
        replaced wholesale (not appended).

        Returns:
            A new :class:`PoCConfig` with merged data.
        """
        defaults = PoCConfig()

        return PoCConfig(
            generator_label=(
                other.generator_label
                if other.generator_label != defaults.generator_label
                else self.generator_label
            ),
            python_template=(
                other.python_template
                if other.python_template != defaults.python_template
                else self.python_template
            ),
            curl_template=(
                other.curl_template
                if other.curl_template != defaults.curl_template
                else self.curl_template
            ),
            markdown_template=(
                other.markdown_template
                if other.markdown_template != defaults.markdown_template
                else self.markdown_template
            ),
        )
