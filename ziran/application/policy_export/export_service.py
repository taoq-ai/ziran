"""Application service for exporting findings as guardrail policies."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from ziran.domain.entities.capability import DangerousChain
from ziran.domain.entities.phase import CampaignResult

if TYPE_CHECKING:
    from ziran.domain.entities.policy import GuardrailPolicy
    from ziran.domain.ports.policy_renderer import PolicyRenderer

SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


class ExportService:
    """Export DangerousChain findings as runtime guardrail policies."""

    def __init__(self, renderer: PolicyRenderer) -> None:
        self._renderer = renderer

    def export(
        self,
        result: CampaignResult,
        severity_floor: str = "medium",
    ) -> list[GuardrailPolicy]:
        """Export findings as guardrail policies.

        Only chains at or above *severity_floor* are rendered.
        """
        floor_value = SEVERITY_ORDER.get(severity_floor, 2)

        policies: list[GuardrailPolicy] = []
        for i, chain_dict in enumerate(result.dangerous_tool_chains):
            chain = DangerousChain.model_validate(chain_dict)
            chain_severity = SEVERITY_ORDER.get(chain.risk_level, 0)
            if chain_severity >= floor_value:
                finding_id = f"ZIRAN-{result.campaign_id}-{i:03d}"
                policy = self._renderer.render(chain, finding_id)
                policies.append(policy)
        return policies

    def export_from_file(
        self,
        result_path: str | Path,
        severity_floor: str = "medium",
    ) -> list[GuardrailPolicy]:
        """Load campaign result from file and export."""
        path = Path(result_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        result = CampaignResult.model_validate(data)
        return self.export(result, severity_floor=severity_floor)
