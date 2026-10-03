"""Usage-tracking decorator over any ``BaseLLMClient`` plus the price-table loader (spec 047).

Wraps an inner client and records each successful call's tokens into a shared
:class:`~ziran.application.usage.UsageLedger` under a stage fixed at construction.
Transparent: it implements the same interface and returns the inner response
unchanged, so call sites do not change.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import ValidationError

from ziran.application.attacks.many_shot import estimate_tokens
from ziran.application.usage import PriceTable
from ziran.infrastructure.llm.base import BaseLLMClient, LLMResponse

if TYPE_CHECKING:
    from ziran.application.usage import Stage, UsageLedger

DEFAULT_PRICE_TABLE = Path(__file__).with_name("prices.yaml")
OVERRIDE_PRICE_TABLE = Path(".ziran/prices.yaml")  # cwd-relative, like .ziran/detectors.yaml


class PriceTableError(ValueError):
    """A price table file is present but invalid."""


class UsageTrackingClient(BaseLLMClient):
    """Records each successful call's tokens into *ledger* under a fixed *stage*."""

    def __init__(self, inner: BaseLLMClient, ledger: UsageLedger, *, stage: Stage) -> None:
        super().__init__(inner.config)
        self._inner = inner
        self._ledger = ledger
        self.stage: Stage = stage

    async def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        response = await self._inner.complete(
            messages, temperature=temperature, max_tokens=max_tokens, **kwargs
        )
        # A provider reporting 0 tokens means "unknown": fill with the chars/4 heuristic.
        prompt = response.prompt_tokens or estimate_tokens(
            "".join(m.get("content", "") for m in messages)
        )
        completion = response.completion_tokens or estimate_tokens(response.content)
        self._ledger.record(
            self.stage,
            self.config.model,
            prompt,
            completion,
            estimated=not (response.prompt_tokens and response.completion_tokens),
        )
        return response

    async def health_check(self) -> bool:
        return await self._inner.health_check()


def track(client: BaseLLMClient | None, ledger: UsageLedger, stage: Stage) -> BaseLLMClient | None:
    """Wrap *client* in a :class:`UsageTrackingClient`, or return None when it is None."""
    return None if client is None else UsageTrackingClient(client, ledger, stage=stage)


def _read(path: Path) -> PriceTable:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return PriceTable.model_validate(raw)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise PriceTableError(f"invalid price table {path}: {exc}") from exc


def load_price_table(override: Path = OVERRIDE_PRICE_TABLE) -> PriceTable:
    """Shipped table with *override*'s models merged over it per model (when it is a file)."""
    table = _read(DEFAULT_PRICE_TABLE)
    if not override.is_file():
        return table
    extra = _read(override)
    return table.model_copy(update={"models": {**table.models, **extra.models}})
