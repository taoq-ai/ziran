# Feature Specification: per-probe correlation markers

**Feature Branch**: `feat/117-probe-markers`
**Created**: 2026-11-26
**Status**: Draft
**Input**: plan item F-PROBE-MARKERS. Probes carry no correlation marker today
(`git grep -i "traceparent\|x-ziran" ziran/` finds nothing; `HttpAgentAdapter._build_client`
sends only the target's static headers). A blue team cannot tell scan traffic from a real attack,
and cannot join an alert or a trace to the attack that caused it.

## The item in my words

1. A target config takes `probe_markers: traceparent | header | both`. Unset (the default), no
   request changes.
2. With it set, every request the HTTP adapter sends for an attack turn carries the turn's
   markers, on the REST, OpenAI, MCP and A2A protocols:
   - `traceparent`: a W3C trace context header, `00-<trace id>-<parent id>-01`. The trace id is
     derived from the campaign id and the vector id, so all turns of one attack share it; the
     parent id is derived from the turn, so each turn has its own.
   - `header`: `X-Ziran-Probe: <campaign id>/<vector id>/<turn>`.
   - `both`: the two.
3. Each `AttackResult` lists `probe_markers`: per turn, the probe id, the trace id and the UTC
   send time.

**Acceptance (the item's).**

- Given a target with `probe_markers: traceparent`, when a two-turn vector runs, then both
  requests carry valid W3C `traceparent` headers with one trace id, and the attack result lists
  that trace id with both send times.
- Given no `probe_markers`, when the same scan runs, then the requests are byte-identical to
  today's, and a test pins that.

In my words, as tests on the real `HttpAgentAdapter`, `AttackExecutor` and `DetectorPipeline`
over an `httpx.MockTransport`:

- A two-prompt vector the target refuses twice sends two requests. Both `traceparent` values
  match the W3C format with one trace id and two parent ids; the result's two markers carry that
  trace id and ordered send times. This holds on REST and OpenAI, invoked and streamed.
- With no `probe_markers`, each request's method, URL, header names, content type and body
  bytes equal a pinned value. The same test, minus the new arguments, passes on the base commit.

## Requirements

- **FR-001**: `TargetConfig.probe_markers` is `None` by default and accepts only `traceparent`,
  `header` or `both`; it loads from target YAML through `load_target_config`.
- **FR-002**: When unset, the HTTP client is built exactly as before (no request hook).
- **FR-003**: When set, every request one adapter call sends (retries and protocol handshakes in
  that call included) carries the same markers.
- **FR-004**: Concurrent attacks on one adapter keep their own markers (per-task context).
- **FR-005**: `AttackResult.probe_markers` defaults to an empty list, so stored results and
  cache entries still load.
- **FR-006**: No change to detectors, the hybrid judge, role typing, tool aliases, chain
  patterns or study refs.

## Out of scope

- Adapters with no HTTP request of their own (LangChain, LangGraph, CrewAI, AutoGen, OpenAI
  Agents, Bedrock, AgentCore, Anthropic, browser). They call an in-process agent or a vendor SDK;
  there is no request of the target's to mark.
- Discovery probes: they run outside an attack, so they carry no marker.
- A pinned trace id prefix: the research note does not ask for one.

## Assumptions

- The trace id is one per attack, not one per turn. The item's promise says the trace id derives
  from campaign id, attack id and turn, while its acceptance asks for one trace id across both
  turns. The turn goes into the parent id instead. Overturned if the owner wants one trace per
  turn.
- `AttackResult` gains a defaulted field, as spec 116 did with `goal_met`; a dumped result gains
  `probe_markers: []`. "Byte-identical" is read as the requests, per the acceptance.
- The campaign id is `campaign_<unix seconds>`; two scans started in the same second of one
  vector share a trace id. Acceptable for deconfliction; overturned if a blue team needs
  uniqueness across simultaneous scans.
