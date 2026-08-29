# Tasks: OTel metrics export (Prometheus-compatible)

- [ ] T001 `otel` extra — add `opentelemetry-exporter-prometheus` + `opentelemetry-exporter-otlp-proto-http`,
      bump api/sdk floor to `>=1.23` for `create_gauge`; refresh `uv.lock` (`pyproject.toml`).
- [ ] T002 `metrics.py` — no-op-fallback module mirroring `tracing.py`: `_HAS_OTEL` guard, nine
      instruments (FR-003) with the FR-004 label sets, `configure_metrics(endpoint, port)` (Prometheus
      pull + OTLP push readers), recording helpers, `get_meter`, `reset_metrics`
      (`ziran/infrastructure/telemetry/metrics.py`). Unit tests: no-op when unconfigured, configure
      wires readers (mocked exporters), each helper records onto the right instrument, `vector_id`
      only on attack instruments (`tests/unit/test_otel_metrics.py`).
- [ ] T003 `campaign_telemetry.py` — extract campaign span start/finish from `scanner.py` into a
      sub-module that also drives `campaign_started` / `campaign_completed`; rewire `scanner.py` to
      call it (net line reduction, stays <= 750). Unit test the extraction + scanner size guard stays
      green (`ziran/application/agent_scanner/campaign_telemetry.py`).
- [ ] T004 Phase/attack instrumentation — `attack_executor` exposes `provider`; `phase_executor`
      records `attack_started` + `record_attack` (perf_counter duration, refused heuristic) and
      `record_phase` (duration + tokens) + concurrency gauge. Unit test records fire with correct
      labels via a captured meter (`tests/unit/test_otel_metrics.py`).
- [ ] T005 CLI — `--metrics-endpoint` / `--metrics-port` on `scan`, call `configure_metrics`
      (`ziran/interfaces/cli/main.py`). Unit test the options parse and wire (mock configure).
- [ ] T006 Integration — live Prometheus pull endpoint on a free port; record instruments; scrape
      `GET /metrics`; assert metric names + labels present (`tests/integration/test_metrics_scrape.py`).
- [ ] T007 Assets/docs — Grafana dashboard JSON + README under `examples/11-observability/`;
      self-contained metrics section in `docs/reference/observability.md`; mkdocs nav entry.
- [ ] T008 Gates — ruff, ruff format, mypy strict, pytest --cov >= 85%; scanner + sub-module size
      tests green.
