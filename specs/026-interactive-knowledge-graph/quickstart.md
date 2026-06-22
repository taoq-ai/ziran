# Quickstart: Interactive Knowledge Graph Visualization

**Feature**: 026-interactive-knowledge-graph

How to work on and verify this feature locally.

## Layout of the change

- **Shared spec (P4)**: `ziran/interfaces/graph_style/graph_style.json` + `spec.py` loader. Single source of truth.
- **Backend graph (P1)**: `ziran/application/knowledge_graph/graph.py` — `export_state()` attaches normalized `centrality` + derived `phase` per node.
- **Report (P1–P3)**: `ziran/interfaces/cli/html_report.py` consumes the spec; gains layout toggle, importance encoding, filters, clustering, scrubber.
- **Persistence (P3)**: migration `003_phase_graph_state.py`, `PhaseResultRow.graph_state_json`, `run_manager` write, `PhaseResultSchema.graph_state`, `routes/runs.py`.
- **UI (P1–P3)**: `ui/src/components/graph/` (`graphStyle.ts`, `graphMapping.ts`, `layouts.ts`, `GraphLegend.tsx`, `GraphControls.tsx`, `KnowledgeGraph.tsx`), `ui/src/pages/RunDetail.tsx`.

## Backend dev loop

```bash
# from repo root
uv run ruff check .
uv run ruff format --check .
uv run mypy ziran/
uv run pytest --cov=ziran            # all pass, coverage >= 85%

# focused tests for this feature
uv run pytest tests/ -k "graph_state or graph_style or phase_snapshot" -v
```

## DB migration (P3)

```bash
# apply the new migration locally (requires ZIRAN_DATABASE_URL)
uv run alembic -c ziran/interfaces/web/alembic.ini upgrade head
# verify phase_results now has graph_state_json
```

## Frontend dev loop

```bash
cd ui
npm install
npm run dev                 # web UI
npm run test:unit           # Vitest unit tests (graphMapping/layouts/graphStyle) — NEW
npm run test:e2e            # Playwright acceptance flows
npm run build               # type-check + bundle (Vite alias @graphstyle -> canonical JSON)
```

## Report generation (verify both surfaces match)

```bash
# generate an HTML report from a sample/recorded run and open it
uv run ziran report ...       # produces a self-contained .html
# confirm: open the file with no network (except vis-network CDN) and verify
#          layout toggle / encoding / filters / scrubber render like the UI
```

## Acceptance verification (per user story)

- **US1 (P1)**: open a multi-phase run → switch to hierarchical layout → nodes band by phase; central nodes larger; high-severity nodes emphasized; toggle a type/severity in the legend hides/shows.
- **US2 (P2)**: large run → auto-clustered overview → expand a phase cluster; start attack-chain walker → step through a path; click a vuln node → finding/attack-log/OWASP-ATLAS opens; click a finding row → node focuses.
- **US3 (P3)**: move the phase scrubber → graph grows phase-by-phase, ending at final state; legacy run → falls back to final state.
- **US4 (P4)**: change a node color in `graph_style.json` → rebuild UI + regenerate report → both reflect it with no other edits.

## Definition of done (per PR)

All gates green: `ruff check`, `ruff format --check`, `mypy ziran/`, `pytest --cov=ziran >= 85%`, frontend `build` + unit + e2e, CI matrix (3.11/3.12/3.13). PR opened against `develop` with labels, CI checked after push.
