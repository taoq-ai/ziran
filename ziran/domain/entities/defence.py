"""Defence-profile domain entities.

Used to declare the defences (input filters, output guards, hybrid guardrail
systems) active on a scan target. Feeds the evasion-rate metric computed in
:mod:`ziran.application.campaign.evasion`.

See spec 012 (Benchmark Maturity), user story 5, and
``specs/012-benchmark-maturity/contracts/defence-profile-yaml.md``.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class DefenceDeclaration(BaseModel):
    """One defence declared as active on a scan target.

    The declaration is advisory: ``evaluable=False`` means ZIRAN records the
    defence in report metadata but has no adapter that can tell whether an
    attack bypassed it. Real guardrail integrations (NeMo Guardrails, Lakera
    Guard, etc.) will flip this to ``True`` in future releases.
    """

    kind: Literal["input_filter", "output_guard", "hybrid"] = Field(
        description="Defence family — where in the request/response pipeline it sits.",
    )
    identifier: str = Field(
        min_length=1,
        description=(
            "Free-form identifier, typically '<product>@<version>' (e.g., 'nemo-guardrails@v0.8')."
        ),
    )
    evaluable: bool = Field(
        default=False,
        description=(
            "True if ZIRAN has an adapter that can evaluate whether an attack "
            "bypassed this defence. False means metadata-only."
        ),
    )


class DefenceProfile(BaseModel):
    """Named declaration of defences active on a target.

    Supplied at scan time via the CLI flag ``--defence-profile`` or via the
    ``defence_profile:`` key in a scan-config YAML. An empty declaration list
    is treated the same as an absent profile — no evasion metric is computed.
    """

    name: str = Field(
        min_length=1,
        description="Free-form profile label (e.g., 'prod-ingress-v1').",
    )
    defences: list[DefenceDeclaration] = Field(
        default_factory=list,
        description="Zero or more defence declarations. Empty = no profile semantically.",
    )

    @property
    def is_empty(self) -> bool:
        """Empty profile is semantically equivalent to no profile at all."""
        return not self.defences

    @property
    def evaluable_defences(self) -> list[DefenceDeclaration]:
        """Defences that ZIRAN can actually test for bypass."""
        return [d for d in self.defences if d.evaluable]
