# Feature Specification: OpenAI Agents SDK adapter

**Feature Branch**: `feat/072-openai-agents-adapter`
**Created**: 2026-11-18
**Status**: Active
**Issue**: #392 (plan item G2-OPENAI-AGENTS)
**Base**: `develop` @ 1f61bdd

## Promise in my own words

A user who built an agent with the OpenAI Agents SDK (`openai-agents`, import name `agents`)
can point `ziran scan` or `ziran discover` at a Python file that defines `agent`, and ziran
scans it in process. Every tool of the agent and of the agents it can hand off to becomes a
capability node; every handoff becomes a delegation edge between agent nodes, so tool chains
across handoffs show up in the knowledge graph. Each attack turn runs the agent with
`Runner.run`, and the tool calls the agent really made reach the detectors, so a refusal that
still sends an email counts as a success.

## Acceptance scenarios (restated)

1. A stub `Agent` with `@function_tool` tools `read_file` and `send_email`, and a handoff to a
   sub-agent with one tool: `discover_capabilities` returns three tool capabilities with name,
   description and parameter schema; `dangerous` is what `is_dangerous` says for each name.
2. The same agent: `discover_structure` returns two agent nodes and one handoff edge from the
   entry agent. After the scanner imports it, the knowledge graph has the tools as nodes and the
   handoff as a `delegates_to` edge.
3. A scripted model that answers with a refusal and calls `send_email` in the same turn:
   `invoke` returns `tool_calls` with `send_email`, its arguments and its output, and the
   side-effect detector fires.
4. `ziran discover --framework openai-agents` (and `scan`) loads the example agent file and
   finds the `agent` object. Without `openai-agents` installed the error names
   `uv sync --extra openai-agents`.
5. `uv lock --check` passes at the PR head and resolves `openai-agents` next to `crewai`.
6. ruff, ruff format, mypy strict and pytest with coverage >= 85% pass.

## Requirements

- **FR-001** `OpenAIAgentsAdapter(agent)` in
  `ziran/infrastructure/adapters/openai_agents_adapter.py`; rejects a non-`agents.Agent` with
  `TypeError`.
- **FR-002** `invoke` runs `Runner.run(agent, history + [user message])`, keeps
  `RunResult.to_input_list()` as history until `reset_state`; maps `ToolCallItem` /
  `ToolCallOutputItem` pairs (by `call_id`) to `{"tool", "input", "output"}`, `final_output`
  to `content`, summed `raw_responses[*].usage` to token counts.
- **FR-003** `discover_capabilities` walks the handoff tree (cycle safe), maps each tool to an
  `AgentCapability` (`tool_<name>`, description, `parameters={"schema": params_json_schema}`,
  `dangerous=is_dangerous(name)`), deduplicated by id.
- **FR-004** `discover_structure` returns a `MultiAgentTopology`: node id
  `openai_agents:<agent name>`, role `agent`, capabilities its tool ids; one edge per handoff,
  `FULL_CONTEXT`, or `PARTIAL_CONTEXT` when the `Handoff` has an `input_filter`; the wrapped
  agent is the entry point. The scanner already imports it (`structure_import`).
- **FR-005** `--framework openai-agents` on `scan` and `discover`; `load_agent_adapter` loads
  `agent`; the `ImportError` names `uv sync --extra openai-agents`.
- **FR-006** Optional extra `openai-agents = ["openai-agents>=0.20,<1"]`, part of `all`;
  `uv.lock` re-locked. No new required dependency.
- **FR-007** `examples/26-openai-agents-scan/` and a `docs/guides/adapters.md` section.

## Out of scope

Native streaming (the base `stream()` fallback serves), tools from `agent.mcp_servers`,
guardrail analysis, realtime and voice agents, the `pentest` command's framework list.

## Assumptions

- The adapter uses the public `Agent`, `Runner`, `RunResult` and `Handoff` API, so it runs on
  0.20 (what the universal lock resolves, crewai caps pydantic) and 0.25 (what a pip user
  without crewai gets). Overturned if the 0.25 API differs; then cap below 0.21.
- One exception: a `Handoff` object exposes its target agent only through the private
  `_agent_ref` weakref. The adapter reads it with `getattr` and falls back to a tool-less node
  named by the public `agent_name`, so a change there loses sub-agent tools, never the edge.
- Agents are identified by `name`; two different agents with one name merge into one node.
- Every turn starts at the wrapped (entry) agent, not at the last agent a handoff reached.
- Spec number: the item names `specs/072-openai-agents-adapter`; the lead brief said 071. The
  item is the source, so 072.
