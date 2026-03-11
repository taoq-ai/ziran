"""Chain pattern registry — YAML-driven dangerous tool chain definitions.

Loads dangerous tool chain patterns from a YAML file instead of
hard-coding them in Python.  This makes patterns easier to maintain,
extend, and override for custom deployments.

Usage::

    registry = ChainPatternRegistry.default()
    patterns = registry.to_dangerous_patterns()
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Re-export the dict value type used by ToolChainAnalyzer._match_pattern
ChainPatternInfo = dict[str, Any]

_DEFAULT_YAML = Path(__file__).parent / "chain_patterns.yaml"


class ChainPattern(BaseModel):
    """A single dangerous tool chain pattern."""

    source: str = Field(description="Substring to match in source tool ID")
    target: str = Field(description="Substring to match in target tool ID")
    type: str = Field(description="Vulnerability type (e.g. data_exfiltration)")
    risk: Literal["critical", "high", "medium", "low"] = Field(description="Risk severity")
    category: str = Field(description="Grouping category (e.g. cloud_services)")
    description: str = Field(description="Human-readable exploit description")
    remediation: str = Field(default="", description="Remediation guidance")


class ChainPatternRegistry(BaseModel):
    """Registry of dangerous tool chain patterns loaded from YAML."""

    patterns: list[ChainPattern] = Field(default_factory=list)

    @classmethod
    def default(cls) -> ChainPatternRegistry:
        """Load the built-in chain patterns shipped with ZIRAN."""
        return cls.from_yaml(_DEFAULT_YAML)

    @classmethod
    def from_yaml(cls, path: Path) -> ChainPatternRegistry:
        """Load patterns from a YAML file.

        Args:
            path: Path to a YAML file with a top-level ``patterns`` list.

        Returns:
            Populated registry.

        Raises:
            FileNotFoundError: If *path* does not exist.
            ValueError: If the YAML structure is invalid.
        """
        with open(path) as fh:
            data = yaml.safe_load(fh)

        if not isinstance(data, dict) or "patterns" not in data:
            msg = f"Expected YAML with a top-level 'patterns' key, got: {type(data)}"
            raise ValueError(msg)

        return cls(patterns=[ChainPattern(**p) for p in data["patterns"]])

    def merge(self, other: ChainPatternRegistry) -> ChainPatternRegistry:
        """Merge another registry into this one.

        Patterns from *other* overwrite patterns with the same
        ``(source, target)`` key.
        """
        seen: dict[tuple[str, str], ChainPattern] = {}
        for p in self.patterns:
            seen[(p.source, p.target)] = p
        for p in other.patterns:
            seen[(p.source, p.target)] = p
        return ChainPatternRegistry(patterns=list(seen.values()))

    def to_dangerous_patterns(self) -> dict[tuple[str, str], ChainPatternInfo]:
        """Convert to the dict format consumed by ``ToolChainAnalyzer``.

        Returns:
            Mapping of ``(source, target)`` → pattern info dict.
        """
        result: dict[tuple[str, str], ChainPatternInfo] = {}
        for p in self.patterns:
            result[(p.source, p.target)] = {
                "type": p.type,
                "risk": p.risk,
                "description": p.description,
                "remediation": p.remediation,
            }
        return result
