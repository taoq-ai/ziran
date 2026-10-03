"""Unit tests for the usage-tracking LLM client decorator and price table (spec 047)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import pytest

from ziran.application.usage import ModelPrice, UsageLedger
from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse
from ziran.infrastructure.llm.usage_tracking_client import (
    DEFAULT_PRICE_TABLE,
    PriceTableError,
    UsageTrackingClient,
    load_price_table,
    track,
)

if TYPE_CHECKING:
    from pathlib import Path


class _UsageStub(BaseLLMClient):
    def __init__(
        self,
        *,
        model: str = "m",
        content: str = '{"verdict":"failure","confidence":0.95}',
        p: int = 100,
        c: int = 20,
        raises: Exception | None = None,
    ) -> None:
        super().__init__(LLMConfig(model=model))
        self.calls = 0
        self.seen: list[tuple[Any, ...]] = []
        self._content, self._p, self._c, self._raises = content, p, c, raises

    async def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        self.calls += 1
        self.seen.append((messages, temperature, max_tokens, kwargs))
        if self._raises is not None:
            raise self._raises
        return LLMResponse(content=self._content, prompt_tokens=self._p, completion_tokens=self._c)

    async def health_check(self) -> bool:
        return True


MSGS = [{"role": "user", "content": "hi"}]


@pytest.mark.unit
class TestDecorator:
    async def test_records_and_returns_same_object(self) -> None:
        stub, ledger = _UsageStub(), UsageLedger()
        client = UsageTrackingClient(stub, ledger, stage="judge")
        assert client.config is stub.config
        first = await client.complete(MSGS)
        await client.complete(MSGS)
        [entry] = ledger.entries()
        assert (entry.stage, entry.model, entry.calls) == ("judge", "m", 2)
        assert (entry.prompt_tokens, entry.completion_tokens) == (200, 40)
        assert entry.estimated_calls == 0
        assert first.content == '{"verdict":"failure","confidence":0.95}'

    async def test_returns_inner_response_identity(self) -> None:
        resp = LLMResponse(content="x", prompt_tokens=1, completion_tokens=1)

        class _Fixed(_UsageStub):
            async def complete(self, messages: Any, **kw: Any) -> LLMResponse:
                return resp

        out = await UsageTrackingClient(_Fixed(), UsageLedger(), stage="judge").complete(MSGS)
        assert out is resp

    async def test_forwards_arguments(self) -> None:
        stub = _UsageStub()
        client = UsageTrackingClient(stub, UsageLedger(), stage="ensemble")
        await client.complete(MSGS, temperature=0.3, max_tokens=7, response_format="json")
        assert stub.seen == [(MSGS, 0.3, 7, {"response_format": "json"})]

    async def test_inner_error_propagates_and_records_nothing(self) -> None:
        ledger = UsageLedger()
        client = UsageTrackingClient(_UsageStub(raises=RuntimeError("boom")), ledger, stage="judge")
        with pytest.raises(RuntimeError, match="boom"):
            await client.complete(MSGS)
        assert ledger.entries() == []

    async def test_health_check_delegates_without_recording(self) -> None:
        ledger = UsageLedger()
        assert await UsageTrackingClient(_UsageStub(), ledger, stage="judge").health_check()
        assert ledger.entries() == []

    async def test_stream_fallback_recorded_once(self) -> None:
        ledger = UsageLedger()
        client = UsageTrackingClient(_UsageStub(), ledger, stage="strategy")
        chunks = [c async for c in client.stream_complete(MSGS)]
        assert len(chunks) == 1
        assert ledger.entries()[0].calls == 1

    def test_track(self) -> None:
        ledger = UsageLedger()
        assert track(None, ledger, "judge") is None
        wrapped = track(_UsageStub(), ledger, "prefilter")
        assert isinstance(wrapped, UsageTrackingClient)
        assert wrapped.stage == "prefilter"


@pytest.mark.unit
class TestHeuristic:
    async def test_zero_usage_filled_by_chars_over_four(self) -> None:
        ledger = UsageLedger()
        stub = _UsageStub(content="r" * 80, p=0, c=0)
        msgs = [{"role": "system", "content": "a" * 150}, {"role": "user", "content": "b" * 250}]
        await UsageTrackingClient(stub, ledger, stage="judge").complete(msgs)
        [e] = ledger.entries()
        assert (e.prompt_tokens, e.completion_tokens, e.estimated_calls) == (100, 20, 1)

    async def test_only_zero_field_filled(self) -> None:
        ledger = UsageLedger()
        stub = _UsageStub(content="r" * 80, p=50, c=0)
        await UsageTrackingClient(stub, ledger, stage="judge").complete(MSGS)
        [e] = ledger.entries()
        assert (e.prompt_tokens, e.completion_tokens, e.estimated_calls) == (50, 20, 1)

    async def test_reported_usage_not_estimated(self) -> None:
        ledger = UsageLedger()
        await UsageTrackingClient(_UsageStub(), ledger, stage="judge").complete(MSGS)
        assert ledger.entries()[0].estimated_calls == 0


@pytest.mark.unit
class TestPriceTable:
    def test_shipped_table_loads(self, tmp_path: Path) -> None:
        assert DEFAULT_PRICE_TABLE.is_file()
        table = load_price_table(tmp_path / "absent.yaml")
        assert table.version == 1
        assert table.currency == "USD"

    def test_every_shipped_price_cites_a_source(self) -> None:
        table = load_price_table(DEFAULT_PRICE_TABLE.with_name("absent.yaml"))
        text = DEFAULT_PRICE_TABLE.read_text(encoding="utf-8")
        for model in table.models:
            line = next(ln for ln in text.splitlines() if re.match(rf"\s+{re.escape(model)}:", ln))
            assert "# source: http" in line, model

    def test_override_merged_per_model(self, tmp_path: Path) -> None:
        path = tmp_path / "prices.yaml"
        path.write_text(
            "version: 1\nmodels:\n  m: {input_per_mtok: 2.5, output_per_mtok: 10}\n",
            encoding="utf-8",
        )
        table = load_price_table(path)
        assert table.models["m"] == ModelPrice(input_per_mtok=2.5, output_per_mtok=10)

    def test_empty_override_is_ok(self, tmp_path: Path) -> None:
        path = tmp_path / "prices.yaml"
        path.write_text("", encoding="utf-8")
        assert load_price_table(path) == load_price_table(tmp_path / "absent.yaml")

    @pytest.mark.parametrize(
        "body",
        [
            "models: [unclosed",
            "models: {}\nbogus: 1\n",
            "models:\n  m: {input_per_mtok: -1, output_per_mtok: 1}\n",
            "- just\n- a list\n",
        ],
    )
    def test_invalid_override_raises(self, tmp_path: Path, body: str) -> None:
        path = tmp_path / "prices.yaml"
        path.write_text(body, encoding="utf-8")
        with pytest.raises(PriceTableError) as exc:
            load_price_table(path)
        assert str(exc.value).startswith(f"invalid price table {path}: ")
