# Contract: Adapter / Orchestrator Migration

**Satisfies**: FR-005; verified by existing tests (no behavior change to the public adapter interfaces)

The framework integrations are refactored onto the new majors **behind their existing interfaces** — callers and the `BaseAgentAdapter` contract are unchanged.

## CrewAI adapter (`crewai_adapter.py`) — crewai 1.14

| Aspect | Requirement |
|---|---|
| Construction | `CrewAIAdapter(crew)` still accepts a `crewai.Crew`; `crew.agents` / `crew.tasks` introspection still works |
| Invoke | `invoke()` still bridges sync `kickoff()` via `asyncio.to_thread`; **must handle the 1.x `CrewOutput` return** (extract `.raw`/text) when populating `AgentResponse.content` |
| Capabilities | the discover/capabilities path still enumerates agents |
| Test oracle | `tests/integration/test_crewai_adapter.py`, `tests/unit/test_langchain_crewai_adapters.py` pass |

## LangChain adapter (`langchain_adapter.py`) — langchain 1.x

| Aspect | Requirement |
|---|---|
| Imports | `AgentExecutor` and the community callbacks import resolve on langchain 1.x (migrated to their new homes, not pinned back) |
| Invoke | wrapping + invoking a LangChain agent still returns the expected `AgentResponse` |
| Test oracle | the langchain adapter unit/integration tests pass + a representative scan completes |

## Pentest orchestrator (`pentesting/agent.py`) — langgraph 1.2

| Aspect | Requirement |
|---|---|
| Graph build | `StateGraph(AgentState)` + `add_node`/`add_edge`/`compile()` build and run on langgraph 1.x |
| Checkpointer | unchanged — compiled **without** a checkpointer (preserves the spec-024 reachability property) |
| Test oracle | the pentest-eval path / its tests pass |

## CLI rendering (rich 14) — 7 importers

| Aspect | Requirement |
|---|---|
| Surfaces | `Console`, `Table`, `Live`, `Panel`, `Prompt`, `Spinner`, `RichHandler` render without error on rich 14 |
| Output | tables, reports, and progress display correctly (FR-003/SC-003) — spot-checked via real CLI commands (`library`, `audit`, a scan summary) |

## LLM client (`litellm_client.py`) — openai 2.x via litellm 1.89

| Aspect | Requirement |
|---|---|
| Calls | `litellm.acompletion`/`aembedding` still succeed through the client wrapper; no direct openai-SDK migration needed |
| Test oracle | the litellm client smoke + adaptive-LLM strategy tests pass |

**Cross-cutting**: `mypy ziran/` stays clean across all refactors (Principle II); no compatibility shims or version pin-arounds (Principle VI).
