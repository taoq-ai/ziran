# Quickstart: Dependency Modernization (#332 Option C)

**Feature**: 025-dependency-modernization | **Date**: 2026-06-22

## Foundational — relax caps + re-lock

```bash
# In pyproject.toml raise the floors (see contracts/target-resolution.md):
#   crewai>=1.14,<2 ; rich>=13.7,<15 ; litellm>=1.84,<2
#   langchain>=1.0,<2 ; langchain-community>=0.4,<2 ; langchain-openai>=1.0,<2
#   langchain-core>=1.0,<2 ; langgraph>=1.0,<2
uv lock                       # MUST resolve (EXIT 0)
uv sync --frozen --extra all --group test
# expect: crewai 1.14.7, rich 14.3.4, litellm 1.89.3, openai 2.43, langchain-core 1.4.8, langgraph 1.2.2
```

## Refactor (US2) — migrate the framework integrations

```bash
# CrewAI adapter: handle the 1.x CrewOutput return type
# LangChain adapter: fix AgentExecutor + langchain_community callback imports for 1.0
# pentest orchestrator: confirm StateGraph API on langgraph 1.2
# rich 14: verify the 7 rich importers render
uv run mypy ziran/                      # must stay clean (Principle II)
uv run pytest -m "unit or integration" -k "crewai or langchain or pentest or litellm" -v
```

## Verify outcome (US1) — gates + alerts fixed

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy ziran/
uv run pytest --cov=ziran            # CI floor: --cov-fail-under=80
cd ui && npm run build && cd ..
# CLI render spot-check on rich 14:
uv run ziran library ; uv run ziran audit examples/19-pentesting-agent/pentest_vulnerable_agent.py
```

## Reconcile records (US3)

```bash
# Remove the now-fixed rows from docs/security/risk-acceptances.md
# Remove their GHSAs from the .github/workflows/ci.yml pip-audit --ignore-vuln list
# Keep only: langchain #108 (if unfixed), chromadb #84, diskcache #41
```

## Acceptance (maps to Success Criteria)

1. **SC-001** — litellm + langchain-family alerts show *fixed* (resolved by upgrade), not dismissed.
2. **SC-002** — no new Dependabot alert of any severity; open critical/high stays 0.
3. **SC-003** — CLI tables/reports/progress render correctly on rich 14.
4. **SC-004** — full gate suite + frontend build green; a representative scan completes.
5. **SC-005** — pip-audit ignore list contains only the no-fix items; the audit gate passes.
6. **SC-006** — CrewAI/LangChain/pentest tests pass on the new majors.

## Quality gates (before PR)

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy ziran/ && uv run pytest --cov=ziran
cd ui && npm run build
```
