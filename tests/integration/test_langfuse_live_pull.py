"""Live Langfuse pull (spec 074) against a mock public API (httpx.MockTransport).

The mock serves ``GET /api/public/v2/observations`` in the documented
``ObservationsV2Response`` shape (``data`` plus ``meta.cursor``; ``input`` as a raw string),
https://cloud.langfuse.com/generated/api/openapi.yml (``observations_getMany``).
"""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from click.testing import CliRunner

from ziran.infrastructure.trace_ingestors import langfuse_ingestor
from ziran.infrastructure.trace_ingestors.langfuse_ingestor import LangfuseIngestor
from ziran.interfaces.cli import analyze_traces as cli_module
from ziran.interfaces.cli.main import cli

PUBLIC = "pk-lf-test-public"
SECRET = "sk-lf-test-secret"
FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "langfuse_v2_observations_page.json"


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _obs(
    oid: str, trace: str, session: str, name: str, start: datetime, kind: str = "SPAN"
) -> dict[str, Any]:
    return {
        "id": oid,
        "traceId": trace,
        "sessionId": session,
        "projectId": "proj-1",
        "type": kind,
        "name": name,
        "startTime": _iso(start),
        "endTime": _iso(start + timedelta(seconds=1)),
        "input": json.dumps({"path": "/etc/passwd"} if name == "read_file" else {"url": "x"}),
        "output": '"ok"',
    }


def _trace(trace: str, session: str, start: datetime) -> list[dict[str, Any]]:
    """One trace: read_file then http_request, a critical data_exfiltration chain."""
    return [
        _obs(f"{trace}-1", trace, session, "read_file", start),
        _obs(f"{trace}-2", trace, session, "http_request", start + timedelta(seconds=2), "TOOL"),
    ]


class MockLangfuse:
    """Filters by fromStartTime and sessionId, pages by ``page_size`` with an opaque cursor."""

    def __init__(self, observations: list[dict[str, Any]], page_size: int = 4) -> None:
        self.observations = observations
        self.page_size = page_size
        self.requests: list[httpx.Request] = []
        self.rate_limit_left = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.url.path == "/api/public/v2/observations"
        if self.rate_limit_left:
            self.rate_limit_left -= 1
            return httpx.Response(429, headers={"Retry-After": "1"}, json={"message": "slow"})
        params = request.url.params
        rows = sorted(self.observations, key=lambda o: o["startTime"])
        if "fromStartTime" in params:
            low = datetime.fromisoformat(params["fromStartTime"].replace("Z", "+00:00"))
            rows = [
                o
                for o in rows
                if datetime.fromisoformat(o["startTime"].replace("Z", "+00:00")) >= low
            ]
        if "sessionId" in params:
            rows = [o for o in rows if o["sessionId"] == params["sessionId"]]
        offset = int(params.get("cursor", "0"))
        page = rows[offset : offset + self.page_size]
        meta: dict[str, Any] = {}
        if offset + self.page_size < len(rows):
            meta["cursor"] = str(offset + self.page_size)
        return httpx.Response(200, json={"data": page, "meta": meta})

    @property
    def pulls(self) -> int:
        """Number of pulls: requests without a cursor start a new one."""
        return sum(1 for r in self.requests if "cursor" not in r.url.params)


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", PUBLIC)
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", SECRET)
    monkeypatch.setenv("LANGFUSE_HOST", "https://lf.test")
    monkeypatch.chdir(tmp_path)

    async def _no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(langfuse_ingestor.asyncio, "sleep", _no_sleep)
    return tmp_path


def _wire(monkeypatch: pytest.MonkeyPatch, mock: MockLangfuse) -> None:
    monkeypatch.setattr(
        cli_module,
        "_build_ingestor",
        lambda source: LangfuseIngestor(transport=httpx.MockTransport(mock.handler)),
    )


def _invoke(*extra: str) -> Any:
    args = ["analyze-traces", "--source", "langfuse", "--out", "out", *extra]
    return CliRunner().invoke(cli, args)


def _report(tmp: Path) -> dict[str, Any]:
    return json.loads((tmp / "out" / "trace_analysis.json").read_text())


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


@pytest.mark.integration
class TestLivePull:
    def test_pages_since_and_basic_auth(self, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        t0 = _now() - timedelta(hours=2)
        old = _trace("old", "s9", _now() - timedelta(days=3))
        mock = MockLangfuse(
            _trace("a", "s1", t0)
            + _trace("b", "s2", t0 + timedelta(minutes=1))
            + _trace("c", "s1", t0 + timedelta(minutes=2))
            + old
        )
        _wire(monkeypatch, mock)

        result = _invoke("--since", "24h")

        assert result.exit_code == 1, result.output  # critical chain matched
        assert len(mock.requests) == 2  # 6 observations, page size 4
        expected = "Basic " + base64.b64encode(f"{PUBLIC}:{SECRET}".encode()).decode()
        assert all(r.headers["authorization"] == expected for r in mock.requests)
        since = datetime.fromisoformat(mock.requests[0].url.params["fromStartTime"])
        assert timedelta(hours=23) < _now() - since < timedelta(hours=25)
        report = _report(env)
        assert report["metadata"]["sessions_analyzed"] == 3
        chain = report["dangerous_tool_chains"][0]
        assert chain["tools"] == ["read_file", "http_request"]
        sessions = sorted(s["session_id"] for s in chain["evidence"]["sessions"])
        assert sessions == ["s1", "s1", "s2"]
        assert PUBLIC not in result.output and SECRET not in result.output

    def test_session_filter(self, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        t0 = _now() - timedelta(hours=1)
        mock = MockLangfuse(_trace("a", "s1", t0) + _trace("b", "s2", t0))
        _wire(monkeypatch, mock)

        result = _invoke("--session-id", "s1")

        assert result.exit_code == 1, result.output
        assert mock.requests[0].url.params["sessionId"] == "s1"
        assert _report(env)["metadata"]["sessions_analyzed"] == 1

    def test_incremental_pulls_only_new(self, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        t0 = _now() - timedelta(hours=1)
        mock = MockLangfuse(_trace("a", "s1", t0) + _trace("b", "s2", t0 + timedelta(minutes=1)))
        _wire(monkeypatch, mock)

        first = _invoke("--incremental")
        assert first.exit_code == 1, first.output
        assert _report(env)["metadata"]["sessions_analyzed"] == 2

        newest = _iso(t0 + timedelta(minutes=1, seconds=2))
        mock.observations += _trace("c", "s3", t0 + timedelta(minutes=5))
        mock.requests.clear()
        second = _invoke("--incremental")

        assert second.exit_code == 1, second.output
        sent = datetime.fromisoformat(mock.requests[0].url.params["fromStartTime"])
        assert sent == datetime.fromisoformat(newest.replace("Z", "+00:00"))
        report = _report(env)
        assert report["metadata"]["sessions_analyzed"] == 1
        assert report["dangerous_tool_chains"][0]["evidence"]["sessions"][0]["session_id"] == "s3"
        cache_files = list((env / ".ziran" / "trace_cache").glob("langfuse-*.json"))
        assert len(cache_files) == 1
        assert len(cache_files[0].stem) == len("langfuse-") + 12
        text = cache_files[0].read_text()
        assert PUBLIC not in text and SECRET not in text

        mock.requests.clear()
        third = _invoke("--incremental")
        assert third.exit_code == 0, third.output
        assert _report(env)["metadata"]["sessions_analyzed"] == 0

    def test_incremental_cursor_not_saved_on_failure(
        self, env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock = MockLangfuse(_trace("a", "s1", _now() - timedelta(hours=1)))
        _wire(monkeypatch, mock)
        result = _invoke("--incremental", "--alert")  # --alert without --config: exit 2
        assert result.exit_code == 2, result.output
        assert not (env / ".ziran" / "trace_cache").exists()

    def test_corrupt_cursor_exits_two(self, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = MockLangfuse(_trace("a", "s1", _now() - timedelta(hours=1)))
        _wire(monkeypatch, mock)
        assert _invoke("--incremental").exit_code == 1
        (cache,) = (env / ".ziran" / "trace_cache").glob("*.json")
        cache.write_text("{not json")
        result = _invoke("--incremental")
        assert result.exit_code == 2, result.output
        assert "delete it" in result.output

    def test_429_once_then_success(self, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = MockLangfuse(_trace("a", "s1", _now() - timedelta(hours=1)))
        mock.rate_limit_left = 1
        waits: list[float] = []

        async def _sleep(seconds: float) -> None:
            waits.append(seconds)

        monkeypatch.setattr(langfuse_ingestor.asyncio, "sleep", _sleep)
        _wire(monkeypatch, mock)

        result = _invoke()

        assert result.exit_code == 1, result.output
        assert waits == [1.0]
        assert _report(env)["metadata"]["sessions_analyzed"] == 1

    def test_429_forever_exits_two(self, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = MockLangfuse([])
        mock.rate_limit_left = 100
        _wire(monkeypatch, mock)

        result = _invoke()

        assert result.exit_code == 2, result.output
        assert "rate limit" in result.output.lower()
        assert len(mock.requests) == 4  # first try plus 3 retries

    def test_http_error_exits_two(self, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _deny(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"message": "Invalid credentials"})

        monkeypatch.setattr(
            cli_module,
            "_build_ingestor",
            lambda source: LangfuseIngestor(transport=httpx.MockTransport(_deny)),
        )
        result = _invoke()
        assert result.exit_code == 2, result.output
        assert "401" in result.output
        assert SECRET not in result.output

    @pytest.mark.parametrize("missing", ["LANGFUSE_SECRET_KEY", "LANGFUSE_PUBLIC_KEY"])
    def test_missing_key_exits_two(
        self,
        env: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        missing: str,
    ) -> None:
        monkeypatch.delenv(missing)
        mock = MockLangfuse([])
        _wire(monkeypatch, mock)

        result = _invoke("-v")

        assert result.exit_code == 2, result.output
        assert "LANGFUSE_PUBLIC_KEY" in result.output and "LANGFUSE_SECRET_KEY" in result.output
        assert mock.requests == []
        logged = result.output + caplog.text
        assert PUBLIC not in logged and SECRET not in logged

    def test_bad_since_exits_two(self, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire(monkeypatch, MockLangfuse([]))
        result = _invoke("--since", "yesterday")
        assert result.exit_code == 2, result.output
        assert "--since" in result.output

    def test_iso_since_and_project_filter(self, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        t0 = _now() - timedelta(hours=1)
        other = _trace("x", "s2", t0)
        for o in other:
            o["projectId"] = "proj-2"
        mock = MockLangfuse(_trace("a", "s1", t0) + other)
        _wire(monkeypatch, mock)

        result = _invoke("--since", "2026-01-01", "--project-id", "proj-1")

        assert result.exit_code == 1, result.output
        assert mock.requests[0].url.params["fromStartTime"].startswith("2026-01-01T00:00:00")
        assert _report(env)["metadata"]["sessions_analyzed"] == 1

    def test_alert_uses_one_pull(self, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = MockLangfuse(_trace("a", "s1", _now() - timedelta(hours=1)))
        _wire(monkeypatch, mock)
        config = env / "alerts.yaml"
        config.write_text("alerts:\n  - kind: slack\n    webhook_url: https://hooks.example/x\n")

        result = _invoke("--alert", "--dry-run-alerts", "--config", str(config))

        assert result.exit_code == 1, result.output
        assert "Alerts:" in result.output
        assert mock.pulls == 1


@pytest.mark.integration
def test_documented_page_shape_parses() -> None:
    """The fixture page (documented schema) yields one session with TOOL and SPAN calls."""
    page = json.loads(FIXTURE.read_text())

    def _serve(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=page)

    ingestor = LangfuseIngestor(transport=httpx.MockTransport(_serve))
    env = {"LANGFUSE_PUBLIC_KEY": PUBLIC, "LANGFUSE_SECRET_KEY": SECRET}
    with pytest.MonkeyPatch.context() as mp:
        for key, value in env.items():
            mp.setenv(key, value)
        sessions = asyncio.run(ingestor.ingest("api", since="2026-11-01"))

    assert len(sessions) == 1
    calls = sessions[0].tool_calls
    assert [c.tool_name for c in calls] == ["read_file", "http_request"]
    assert calls[0].arguments == {"path": "/etc/passwd"}
    assert sessions[0].session_id == "s1"
