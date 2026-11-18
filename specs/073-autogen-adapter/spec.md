# Feature Specification: AutoGen AgentChat adapter

**Feature Branch**: `feat/073-autogen-adapter`
**Created**: 2026-11-18
**Status**: Active
**Issue**: #285 (plan item G2-AUTOGEN)
**Base**: `develop` @ c0a5586

## Promise in my own words

A user who built an agent or a team with Microsoft AutoGen AgentChat (`autogen-agentchat` 0.7,
import name `autogen_agentchat`) can point `ziran scan` or `ziran discover` at a Python file
that defines `team` or `agent`, and ziran scans it in process. Every tool of every agent in the
team, nested teams included, becomes a capability; every team member becomes an agent node, and
the way the team passes turns (round robin, a selector, Swarm handoffs) becomes edges between
them. Each attack turn awaits `run(task=message)`, and the tool calls the agents really made
reach the detectors, so a refusal that still sends an email counts as a success.

## Acceptance scenarios (restated)

1. An `AssistantAgent` with tools `read_file` and `send_email`: `discover_capabilities` returns
   both with name, description and JSON parameter schema; `dangerous` is what `is_dangerous`
   says for each name.
2. A `RoundRobinGroupChat` of a writer and a reviewer: `discover_structure` returns two agent
   nodes with edges between them, and the scanner imports them into the knowledge graph. A
   `Swarm` whose agent has a handoff gives a handoff edge.
3. A stub model client (written in the test, no `autogen-ext`) that calls `send_email` and
   replies with a refusal: `invoke` returns `tool_calls` with `send_email`, its arguments and
   its result, and the side-effect detector fires.
4. `ziran discover --framework autogen examples/27-autogen-agent/agent.py` finds the team.
   Without `autogen-agentchat` installed the error names `uv sync --extra autogen`.
5. `uv lock --check` passes at the PR head with `autogen-agentchat` 0.7.x.
6. ruff, ruff format, mypy strict and pytest with coverage >= 85% pass.

## Requirements

- **FR-001** `AutoGenAdapter(target)` in `ziran/infrastructure/adapters/autogen_adapter.py`
  accepts an `autogen_agentchat.base.ChatAgent` or `Team`; anything else is a `TypeError`.
- **FR-002** `invoke` awaits `target.run(task=message)` under a lock (a team refuses a second
  concurrent run); maps `ToolCallRequestEvent` / `ToolCallExecutionEvent` pairs (by call id) to
  `{"tool", "input", "output"}`, the last chat message that is not the task to `content`, and
  summed `models_usage` to token counts. Conversation state stays inside the AutoGen object, so
  turns accumulate until a reset.
- **FR-003** `reset_state` is synchronous in the port while AutoGen's reset is async, so it
  marks a reset that the next `invoke` awaits first: `Team.reset()` or
  `ChatAgent.on_reset(...)`.
- **FR-004** `discover_capabilities` walks the target and nested team participants, lists each
  agent's tools through its workbenches' public `list_tools()` (the workbenches are reachable
  only through the private `_workbench` attribute), and maps each to an `AgentCapability`
  (`tool_<name>`, description, `parameters={"schema": parameters}`,
  `dangerous=is_dangerous(name)`), deduplicated by id.
- **FR-005** `discover_structure` returns a `MultiAgentTopology`: node `autogen:<name>` per
  agent, role `human` for a `UserProxyAgent`, else `agent`. Round robin: a ring of unconditional
  edges, topology `peer_to_peer`. Selector: a router node for the team with conditional edges
  to each member, topology `router`. Swarm: one conditional edge per handoff, labelled with the
  handoff name, topology `peer_to_peer`. A nested team is a node (role `team`, or `router` for a
  selector) with edges to its members.
- **FR-006** `--framework autogen` on `scan` and `discover`; `load_agent_adapter` loads `team`,
  else `agent`; the `ImportError` names `uv sync --extra autogen`.
- **FR-007** Optional extra `autogen = ["autogen-agentchat>=0.7,<0.8"]`, part of `all`;
  `uv.lock` re-locked; `autogen_agentchat.*` and `autogen_core.*` in the mypy
  `ignore_missing_imports` overrides, since CI type-checks without extras.
- **FR-008** `examples/27-autogen-agent/` (a code-writer team, as the issue asks) and a
  `docs/guides/adapters.md` section.
- **FR-009** A test fails if the private attributes the adapter reads (`_workbench`,
  `_participants`, `_handoffs`) disappear.

## Out of scope

AG2 (PyPI `autogen` 0.14 classic API, `ag2` 1.x), Microsoft Agent Framework, native
`run_stream` (the base `stream()` fallback meets the issue's streaming wish), MagenticOne,
GraphFlow edges (its members still become nodes), code-executor sandbox analysis, agents nested
inside a `SocietyOfMindAgent` or wrapped as `AgentTool` / `TeamTool` (they show as one tool).

## Assumptions

- Owner decision (scope:, 2026-11-18): "AutoGen" means Microsoft's `autogen-agentchat` 0.7, the
  package the issue links and the one `pyautogen` 0.10 now proxies, not AG2's classic
  `GroupChat` / `function_map` API that the issue text names. Overturned if the owner wants AG2;
  then the adapter targets that package.
- Tools, team members and handoffs are reachable only through private attributes
  (`_workbench`, `_participants`, `_handoffs`), so the extra pins `<0.8`. A missing attribute
  degrades to no tools or no members (read with `getattr`), and a unit test fails if one is
  gone, so a version bump shows it.
- Agents and nested teams are identified by name; AutoGen requires unique names within a team,
  but two nested teams that keep the default class name merge into one node.
- Group chat members all see the whole thread, so every edge is `full_context`.
- A team without a termination condition runs forever in AutoGen too; the adapter does not add
  one. The docs say so.
- Spec number 073 and example 27 come from the item; both were free (`ls specs/ examples/`,
  `git branch -a`).
