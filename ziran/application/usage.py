"""Per-campaign token and cost accounting with a cooperative budget (spec 047).

Every LLM call made for a campaign is recorded in a :class:`UsageLedger` keyed by
``(stage, model)``. Stages: ``judge`` (single judge), ``ensemble`` (ensemble members
with their own model), ``prefilter`` (cheap first-pass judge), ``strategy``
(LLM-adaptive strategy) and ``target`` (the agent under test, never priced).

A :class:`PriceTable` turns tokens into an estimated USD cost; a model without a
price costs ``None`` (unknown), never ``0``. A :class:`CampaignBudget` is checked
cooperatively before each vector and each phase: attacks already running finish,
so the totals can overshoot the cap by up to the concurrency limit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from ziran.domain.entities.phase import ScanPhase

logger = get_logger(__name__)

Stage = Literal["judge", "ensemble", "prefilter", "strategy", "target"]
STAGES: tuple[Stage, ...] = ("judge", "ensemble", "prefilter", "strategy", "target")
TARGET_MODEL = "unknown"  # model key for the target stage; the target is never priced


class ModelPrice(BaseModel):
    """List price of one model in USD per 1,000,000 tokens."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    input_per_mtok: float = Field(ge=0)
    output_per_mtok: float = Field(ge=0)


class PriceTable(BaseModel):
    """Model prices (shipped table merged with the operator override)."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    version: Literal[1] = 1
    currency: Literal["USD"] = "USD"
    models: dict[str, ModelPrice] = Field(default_factory=dict)

    def price_for(self, model: str) -> ModelPrice | None:
        """Exact model name first, then the part after the last '/'; None when absent."""
        return self.models.get(model) or self.models.get(model.rsplit("/", 1)[-1])

    def cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> float | None:
        """Estimated USD cost rounded to 6 decimals; None when the model has no price."""
        price = self.price_for(model)
        if price is None:
            return None
        return round(
            prompt_tokens * price.input_per_mtok / 1e6
            + completion_tokens * price.output_per_mtok / 1e6,
            6,
        )


class UsageEntry(BaseModel):
    """Accumulated usage of one (stage, model) pair."""

    stage: Stage
    model: str
    calls: int = Field(default=0, ge=0)
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)  # always prompt + completion
    estimated_calls: int = Field(default=0, ge=0)  # calls where the char heuristic filled a 0
    cost_usd: float | None = None  # filled only in summaries; None = unknown


class UsageBudget(BaseModel):
    """Campaign limits; an unset limit never triggers."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    max_tokens: int | None = Field(default=None, gt=0)
    max_cost_usd: float | None = Field(default=None, gt=0)


class UsageSummary(BaseModel):
    """Serialisable usage breakdown stored in ``CampaignResult.metadata['usage']``."""

    currency: Literal["USD"] = "USD"
    entries: list[UsageEntry]
    total_tokens: int
    total_cost_usd: float | None
    unpriced_tokens: int
    max_campaign_tokens: int | None
    max_cost_usd: float | None


class UsageLedger:
    """Per-campaign accumulator keyed by (stage, model).

    Mutated only on the event-loop thread with no ``await`` between read and
    write, so no lock is needed.
    """

    def __init__(self, prices: PriceTable | None = None) -> None:
        self.prices = prices or PriceTable()
        self._entries: dict[tuple[Stage, str], UsageEntry] = {}

    def record(
        self,
        stage: Stage,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        *,
        estimated: bool = False,
    ) -> None:
        """Add one call's tokens to the (stage, model) entry."""
        e = self._entries.setdefault((stage, model), UsageEntry(stage=stage, model=model))
        e.calls += 1
        e.prompt_tokens += prompt_tokens
        e.completion_tokens += completion_tokens
        e.total_tokens += prompt_tokens + completion_tokens
        e.estimated_calls += int(estimated)

    def total_tokens(self) -> int:
        """All-stage token total (target included)."""
        return sum(e.total_tokens for e in self._entries.values())

    def _cost(self, e: UsageEntry) -> float | None:
        if e.stage == "target":
            return None
        return self.prices.cost(e.model, e.prompt_tokens, e.completion_tokens)

    def total_cost(self) -> float | None:
        """Sum of known costs rounded to 6 decimals; None when no entry is priced."""
        costs = [c for e in self._entries.values() if (c := self._cost(e)) is not None]
        return round(sum(costs), 6) if costs else None

    def entries(self) -> list[UsageEntry]:
        """Copies of the entries with ``cost_usd`` None (checkpoint snapshot)."""
        return [e.model_copy() for e in self._entries.values()]

    def restore(self, entries: Iterable[UsageEntry]) -> None:
        """Add the counts of *entries* to the ledger (resume)."""
        for src in entries:
            e = self._entries.setdefault(
                (src.stage, src.model), UsageEntry(stage=src.stage, model=src.model)
            )
            e.calls += src.calls
            e.prompt_tokens += src.prompt_tokens
            e.completion_tokens += src.completion_tokens
            e.total_tokens += src.total_tokens
            e.estimated_calls += src.estimated_calls

    def summary(self) -> list[UsageEntry]:
        """Entries sorted by stage order then model, with ``cost_usd`` filled."""
        ordered = sorted(self._entries.values(), key=lambda e: (STAGES.index(e.stage), e.model))
        return [e.model_copy(update={"cost_usd": self._cost(e)}) for e in ordered]


class CampaignBudget:
    """Ledger plus limits for one campaign; checked between vectors and phases."""

    def __init__(self, ledger: UsageLedger, limits: UsageBudget) -> None:
        self.ledger = ledger
        self.limits = limits
        self.interrupted_phase: ScanPhase | None = None  # set when a vector is skipped
        self._phase_skipped = False  # set when the phase loop stopped with phases pending
        self._logged = False

    @property
    def stopped(self) -> bool:
        """True only when the cap actually left work undone (skipped vector or phase)."""
        return self.interrupted_phase is not None or self._phase_skipped

    def stop_phases(self, pending: bool) -> bool:
        """Phase-loop check: True once exceeded; marks the run stopped if *pending*."""
        if not self.exceeded():
            return False
        self._phase_skipped = self._phase_skipped or pending
        return True

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> CampaignBudget:
        """Build from ``scanner_config``; raises ``ValidationError`` on invalid limits."""
        return cls(
            config.get("usage_ledger") or UsageLedger(),
            UsageBudget(
                max_tokens=config.get("max_campaign_tokens"),
                max_cost_usd=config.get("max_cost"),
            ),
        )

    def exceeded(self) -> bool:
        """True once a limit is reached (``total >= cap``); logs the first hit."""
        tokens = self.ledger.total_tokens()
        cost = self.ledger.total_cost()
        limit = None
        if self.limits.max_tokens is not None and tokens >= self.limits.max_tokens:
            limit = "tokens"
        elif self.limits.max_cost_usd is not None and (cost or 0.0) >= self.limits.max_cost_usd:
            limit = "cost"
        if limit is not None and not self._logged:
            self._logged = True
            logger.warning(
                "campaign_budget_exceeded",
                limit=limit,
                total_tokens=tokens,
                total_cost_usd=cost,
                max_tokens=self.limits.max_tokens,
                max_cost_usd=self.limits.max_cost_usd,
            )
        return limit is not None

    def summary(self) -> UsageSummary:
        """Breakdown with costs, totals and the configured limits."""
        entries = self.ledger.summary()
        return UsageSummary(
            entries=entries,
            total_tokens=self.ledger.total_tokens(),
            total_cost_usd=self.ledger.total_cost(),
            unpriced_tokens=sum(e.total_tokens for e in entries if e.cost_usd is None),
            max_campaign_tokens=self.limits.max_tokens,
            max_cost_usd=self.limits.max_cost_usd,
        )
