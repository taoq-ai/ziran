"""Unit tests for the campaign usage ledger, pricing and budget (spec 047)."""

from __future__ import annotations

import pytest
import structlog
from pydantic import ValidationError
from structlog.testing import capture_logs

from ziran.application import usage as usage_mod
from ziran.application.usage import (
    STAGES,
    CampaignBudget,
    ModelPrice,
    PriceTable,
    UsageBudget,
    UsageEntry,
    UsageLedger,
)

PRICES = PriceTable(models={"m": ModelPrice(input_per_mtok=2.50, output_per_mtok=10.00)})


@pytest.mark.unit
class TestLedger:
    def test_accumulates_per_stage_and_model(self) -> None:
        ledger = UsageLedger()
        for _ in range(3):
            ledger.record("judge", "m", 100, 20)
        [entry] = ledger.entries()
        assert (entry.stage, entry.model, entry.calls) == ("judge", "m", 3)
        assert (entry.prompt_tokens, entry.completion_tokens, entry.total_tokens) == (300, 60, 360)
        assert entry.estimated_calls == 0

    def test_estimated_flag_counts(self) -> None:
        ledger = UsageLedger()
        ledger.record("judge", "m", 1, 1, estimated=True)
        ledger.record("judge", "m", 1, 1)
        assert ledger.entries()[0].estimated_calls == 1

    def test_distinct_pairs_and_total(self) -> None:
        ledger = UsageLedger()
        ledger.record("judge", "m", 100, 20)
        ledger.record("ensemble", "m", 10, 5)
        ledger.record("judge", "x", 1, 1)
        ledger.record("target", "unknown", 7, 3)
        assert len(ledger.entries()) == 4
        assert ledger.total_tokens() == 120 + 15 + 2 + 10

    def test_entries_are_copies(self) -> None:
        ledger = UsageLedger()
        ledger.record("judge", "m", 100, 20)
        snap = ledger.entries()
        assert snap[0].cost_usd is None
        snap[0].calls = 99
        assert ledger.entries()[0].calls == 1

    def test_restore_fresh_and_additive(self) -> None:
        src = UsageLedger()
        src.record("judge", "m", 100, 20, estimated=True)
        src.record("target", "unknown", 7, 3)
        fresh = UsageLedger()
        fresh.restore(src.entries())
        assert fresh.entries() == src.entries()
        fresh.restore(src.entries())
        assert fresh.total_tokens() == 2 * src.total_tokens()
        judge = next(e for e in fresh.entries() if e.stage == "judge")
        assert (judge.calls, judge.estimated_calls) == (2, 2)

    def test_summary_sorted_by_stage_then_model(self) -> None:
        ledger = UsageLedger()
        ledger.record("target", "unknown", 1, 1)
        ledger.record("judge", "z", 1, 1)
        ledger.record("prefilter", "a", 1, 1)
        ledger.record("judge", "a", 1, 1)
        keys = [(e.stage, e.model) for e in ledger.summary()]
        assert keys == [("judge", "a"), ("judge", "z"), ("prefilter", "a"), ("target", "unknown")]
        assert STAGES == ("judge", "ensemble", "prefilter", "strategy", "target")


@pytest.mark.unit
class TestPricing:
    def test_cost_formula(self) -> None:
        assert PRICES.cost("m", 100, 20) == 0.00045

    def test_three_calls(self) -> None:
        ledger = UsageLedger(PRICES)
        for _ in range(3):
            ledger.record("judge", "m", 100, 20)
        assert ledger.summary()[0].cost_usd == 0.00135
        total = ledger.total_cost()
        assert total is not None
        assert abs(total - 3 * 0.00045) < 1e-9

    def test_rounds_to_six_decimals(self) -> None:
        assert PRICES.cost("m", 1, 0) == round(2.5e-6, 6)
        assert PRICES.cost("m", 1, 1) == round(2.5e-6 + 1e-5, 6)

    def test_suffix_fallback_and_exact_wins(self) -> None:
        assert PRICES.price_for("openai/m") == PRICES.models["m"]
        table = PriceTable(
            models={
                "m": ModelPrice(input_per_mtok=1, output_per_mtok=1),
                "openai/m": ModelPrice(input_per_mtok=5, output_per_mtok=5),
            }
        )
        assert table.price_for("openai/m") == ModelPrice(input_per_mtok=5, output_per_mtok=5)

    def test_unknown_model_is_null_not_zero(self) -> None:
        assert PRICES.cost("nope", 100, 20) is None
        ledger = UsageLedger(PRICES)
        ledger.record("judge", "nope", 100, 20)
        assert ledger.summary()[0].cost_usd is None
        assert ledger.total_cost() is None

    def test_target_never_priced(self) -> None:
        ledger = UsageLedger(PRICES)
        ledger.record("target", "m", 100, 20)
        assert ledger.summary()[0].cost_usd is None
        assert ledger.total_cost() is None

    def test_price_table_rejects_bad_input(self) -> None:
        with pytest.raises(ValidationError):
            PriceTable.model_validate({"models": {}, "extra": 1})
        with pytest.raises(ValidationError):
            PriceTable.model_validate(
                {"models": {"m": {"input_per_mtok": -1, "output_per_mtok": 1}}}
            )
        with pytest.raises(ValidationError):
            PriceTable.model_validate({"version": 2})


@pytest.mark.unit
class TestBudget:
    @pytest.mark.parametrize(
        "kwargs", [{"max_tokens": 0}, {"max_cost_usd": 0}, {"max_tokens": -1}, {"max_cost_usd": -1}]
    )
    def test_invalid_limits(self, kwargs: dict[str, float]) -> None:
        with pytest.raises(ValidationError):
            UsageBudget.model_validate(kwargs)

    def test_no_limits_never_exceeded(self) -> None:
        budget = CampaignBudget(UsageLedger(PRICES), UsageBudget())
        budget.ledger.record("judge", "m", 10**9, 10**9)
        assert not budget.exceeded()

    def test_token_cap_at_cap_counts(self) -> None:
        budget = CampaignBudget(UsageLedger(), UsageBudget(max_tokens=360))
        budget.ledger.record("judge", "m", 300, 59)
        assert not budget.exceeded()
        budget.ledger.record("target", "unknown", 1, 0)
        assert budget.exceeded()

    def test_cost_cap(self) -> None:
        budget = CampaignBudget(UsageLedger(PRICES), UsageBudget(max_cost_usd=0.0004))
        assert not budget.exceeded()
        budget.ledger.record("judge", "m", 100, 20)
        assert budget.exceeded()

    def test_unpriced_calls_never_trip_cost_cap(self) -> None:
        budget = CampaignBudget(UsageLedger(PRICES), UsageBudget(max_cost_usd=0.0001))
        budget.ledger.record("judge", "other", 10**6, 10**6)
        budget.ledger.record("target", "m", 10**6, 10**6)
        assert not budget.exceeded()

    def test_logs_once_without_prompt_text(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Fresh logger: a cached one bound by earlier logging setup bypasses capture_logs.
        monkeypatch.setattr(usage_mod, "logger", structlog.get_logger())
        budget = CampaignBudget(UsageLedger(), UsageBudget(max_tokens=1))
        budget.ledger.record("judge", "m", 5, 5)
        with capture_logs() as logs:
            assert budget.exceeded()
            assert budget.exceeded()
        hits = [e for e in logs if e["event"] == "campaign_budget_exceeded"]
        assert len(hits) == 1
        assert hits[0]["limit"] == "tokens"
        assert hits[0]["total_tokens"] == 10
        assert set(hits[0]) <= {
            "event",
            "log_level",
            "limit",
            "total_tokens",
            "total_cost_usd",
            "max_tokens",
            "max_cost_usd",
        }

    def test_from_config(self) -> None:
        empty = CampaignBudget.from_config({})
        assert isinstance(empty.ledger, UsageLedger)
        assert empty.limits == UsageBudget()
        assert empty.interrupted_phase is None
        ledger = UsageLedger()
        budget = CampaignBudget.from_config(
            {"usage_ledger": ledger, "max_campaign_tokens": 5, "max_cost": 1.0}
        )
        assert budget.ledger is ledger
        assert budget.limits == UsageBudget(max_tokens=5, max_cost_usd=1.0)
        with pytest.raises(ValidationError):
            CampaignBudget.from_config({"max_campaign_tokens": 0})

    def test_stopped_only_when_work_left(self) -> None:
        budget = CampaignBudget(UsageLedger(), UsageBudget(max_tokens=100))
        assert not budget.stop_phases(pending=True)
        assert not budget.stopped
        budget.ledger.record("judge", "m", 100, 20)
        assert budget.stop_phases(pending=False)
        assert not budget.stopped  # cap reached with nothing left to run
        assert budget.stop_phases(pending=True)
        assert budget.stopped

    def test_summary(self) -> None:
        budget = CampaignBudget(UsageLedger(PRICES), UsageBudget(max_tokens=10_000))
        budget.ledger.record("judge", "m", 100, 20)
        budget.ledger.record("judge", "other", 30, 10)
        budget.ledger.record("target", "unknown", 7, 3)
        s = budget.summary()
        assert s.currency == "USD"
        assert s.total_tokens == 120 + 40 + 10
        assert s.total_cost_usd == 0.00045
        assert s.unpriced_tokens == 50
        assert (s.max_campaign_tokens, s.max_cost_usd) == (10_000, None)
        assert [e.model for e in s.entries] == ["m", "other", "unknown"]
        assert all(isinstance(e, UsageEntry) for e in s.entries)
