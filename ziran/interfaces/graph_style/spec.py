"""Canonical, surface-agnostic knowledge-graph style/mapping specification.

This module is the **single source of truth** for how graph nodes and edges
map to visual properties. Both the interactive web UI (which imports the
sibling ``graph_style.json`` directly) and the self-contained HTML report
(which loads it through this module) render from the same definition, so the
two surfaces cannot drift.

See ``specs/026-interactive-knowledge-graph/contracts/graph-style-spec.md``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

_SPEC_PATH = Path(__file__).with_name("graph_style.json")

# Fallback styling for an unknown node type — matches the neutral agent_state.
_FALLBACK_NODE_TYPE = "agent_state"
_FALLBACK_EDGE_COLOR = "#94a3b8"


class NodeStyle(BaseModel):
    """Visual styling for a single node type."""

    color: str
    border: str
    shape: str
    base_size: float = Field(gt=0)


class EdgeStyle(BaseModel):
    """Visual styling for a single edge type."""

    color: str
    dashes: bool | list[int] = False
    width: float = Field(gt=0)
    arrow: bool = True


class DangerMarker(BaseModel):
    """Emphasis applied to nodes flagged as dangerous capabilities."""

    border_color: str
    border_width: float = Field(gt=0)
    shadow_color: str
    shadow_size: float = Field(gt=0)


class SizeEncoding(BaseModel):
    """Maps a normalized centrality value (0..1) onto a node pixel size."""

    min_size: float = Field(gt=0)
    max_size: float = Field(gt=0)

    @model_validator(mode="after")
    def _check_span(self) -> SizeEncoding:
        # A non-positive span would invert or collapse centrality sizing.
        if self.max_size <= self.min_size:
            raise ValueError("size_encoding.max_size must be greater than min_size")
        return self


class Thresholds(BaseModel):
    """Tunable thresholds shared by both surfaces."""

    large_graph_node_threshold: int = Field(gt=0)
    auto_cluster: bool = True


class GraphStyleSpec(BaseModel):
    """The complete graph style/mapping specification."""

    version: str
    node_types: dict[str, NodeStyle]
    edge_types: dict[str, EdgeStyle]
    severity_ramp: dict[str, str]
    danger_marker: DangerMarker
    phase_order: list[str] = Field(min_length=1)
    size_encoding: SizeEncoding
    attack_edge_types: list[str]
    thresholds: Thresholds

    def node_style(self, node_type: str) -> NodeStyle:
        """Return styling for ``node_type``, falling back to the neutral style."""
        return self.node_types.get(node_type) or self.node_types[_FALLBACK_NODE_TYPE]

    def edge_style(self, edge_type: str) -> EdgeStyle:
        """Return styling for ``edge_type``, synthesizing a neutral default."""
        return self.edge_types.get(edge_type) or EdgeStyle(color=_FALLBACK_EDGE_COLOR, width=1.5)

    def severity_color(self, severity: str | None) -> str | None:
        """Return the ramp color for ``severity`` (case-insensitive), or None."""
        if not severity:
            return None
        return self.severity_ramp.get(severity.lower())

    def size_for_centrality(self, centrality: float | None) -> float:
        """Map a normalized centrality (0..1) to a node size within bounds.

        Missing or out-of-range values degrade gracefully to ``min_size``.
        """
        c = 0.0 if centrality is None else max(0.0, min(1.0, centrality))
        span = self.size_encoding.max_size - self.size_encoding.min_size
        return self.size_encoding.min_size + span * c

    def node_size(self, node_type: str, centrality: float | None) -> float:
        """Effective node size: the type's base size, grown by centrality.

        This is the canonical sizing rule shared by both surfaces — the
        per-type ``base_size`` is the floor so node shapes stay legible, and
        a pivotal (high-centrality) node grows up to ``max_size``.
        """
        return max(self.node_style(node_type).base_size, self.size_for_centrality(centrality))

    def phase_level(self, phase: str | None) -> int:
        """Hierarchical-layout column for ``phase``.

        Phases map to columns ``1..N`` in methodology order; unattributed
        nodes go to column ``0`` (the leading "unassigned" band).
        """
        if phase is None:
            return 0
        try:
            return self.phase_order.index(phase) + 1
        except ValueError:
            return 0

    def is_attack_edge(self, edge_type: str) -> bool:
        """Whether ``edge_type`` is attack-relevant (emphasized in the viz)."""
        return edge_type in self.attack_edge_types


@lru_cache(maxsize=1)
def load_graph_style() -> GraphStyleSpec:
    """Load and validate the canonical graph style spec (cached)."""
    raw = json.loads(_SPEC_PATH.read_text(encoding="utf-8"))
    return GraphStyleSpec.model_validate(raw)
