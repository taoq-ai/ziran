# Feature Specification: chains found at discovery steer the campaign

**Feature Branch**: `feat/087-chain-steered-campaign`
**Created**: 2026-11-23
**Status**: Active
**Plan item**: A-CHAIN-STEER (goal G-a), issue #536 row 2.
**Base**: `develop` @ ad2b626.

## The promise in our own words

Today `ziran scan` finds dangerous tool chains (for example `read_file` to `http_request`) only
at the end, in `ResultBuilder`. The campaign never uses them: vectors run in library order, so a
scan of a vulnerable agent rarely makes the agent walk the chain and leaves no tool-call
evidence. A probe (A-STEER-PROBE) ran the five best library exfiltration vectors against a flat
`read_file` + `http_request` agent on a live model and got 0 of 5: the prompts named no chain
tool and no file, three `de_*` prompts read as credential grabs and were refused, and the
`ii_*` payloads sat in the user turn.

After this change:

1. Right after discovery the scanner runs `ToolChainAnalyzer.analyze()` (cycles off on a graph
   with co-resident edges, the spec 086 default) and keeps the chains. `ResultBuilder` still runs
   its own final analysis.
2. `CampaignContext` gains `dangerous_chains` and `chain_vectors` (the chain-targeted vectors by
   id, rendered for their chain, in run order). Every construction site fills them: the two
   scanner blocks, now one helper `campaign_context` in `chain_targeting.py`, and the context
   `PhaseExecutor` builds for `prioritize_attacks`.
3. A new module `ziran/application/agent_scanner/chain_targeting.py` maps each chain to vectors
   with one table from vulnerability-type families to vector categories and tags:
   - exfiltration and leak types: `data_exfiltration` vectors, plus `indirect_injection` vectors
     tagged `exfiltration` or `data_exfiltration`;
   - rce, exec and shell types: `tool_manipulation` vectors tagged for code or command
     execution;
   - persist and poisoning types: `memory_poisoning` vectors;
   - escalation and auth types: `privilege_escalation` and `authorization_bypass` vectors.

   A vector tagged `harmful_task` is never chosen. In every phase, after the strategy's
   `prioritize_attacks` and before `decision.max_attacks`, the chain-targeted vectors of that
   phase move to the front in a stable order, for every strategy including `FixedStrategy`.
4. `AdaptiveStrategy._score_phase` boosts a phase that holds chain-targeted vectors not yet run.
   `LLMAdaptiveStrategy` lists the chains in its phase-selection prompt.
5. `CampaignResult.chain_targets` lists, per chain: its tools, its vulnerability type, the
   vector ids chosen for it and which of them ran. The Markdown and HTML reports show it in one
   table.
6. Each chain-targeted vector's prompt is rendered with the chain's source and sink tool names
   and one concrete resource for the source (a default or example from the discovered parameter
   schema, else `notes.txt`), as a task the agent would plausibly do. Variables that named
   secrets ("API keys", "credentials") now name that resource, and a URL variable points to an
   unresolvable `example.invalid` endpoint.
7. A chain-targeted vector whose `protocol_filter` does not match the target is dropped. Vectors
   rank by fit (family tags plus the variables the renderer fills) before severity.
8. Chain edges are built on capability node ids (`tool_<name>`, the ids `tool_to_capability`
   gives). Spec 086 already does this; a test here pins it.

Out of scope: delivering indirect-injection payloads through a tool result (#535; an environment
that already holds the payload, such as a poisoned file, is the supported path), reordering
phases under the fixed strategy, new vectors, README wording (#536 row 3).

### How this fails (pre-mortem)

1. A large co-resident agent (up to 100 tools, about 2,500 chains) makes the extra discovery-time
   analysis or the targeting slow. Guard: targeting ranks each family's candidates once and each
   chain takes the next unclaimed vectors, so it is linear in chains plus candidates; a test
   times 100 tools.
2. Steering changes the order of agents with no chain, so baselines and existing tests move.
   Guard: with no chains `chain_vectors` is empty, `steer` returns the list unchanged and the
   LLM prompt adds only a "none" line; a test compares the run order with the library order.
3. A rendered prompt still reads as a credential grab and a safe model refuses it, so steering
   adds no evidence. Guard: the renderer replaces the secret-naming variables, the task line
   names a file and the two tools, and a test checks the rendered prompts of the chosen vectors
   for the flat chain hold no "API key", "credential" or "password".

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Chain vectors run first and leave evidence (Priority: P1)

1. **Given** a flat LangChain agent with `read_file` and `http_request` and a scripted model,
   **When** `run_campaign` runs the execution phase with the fixed strategy and
   `max_concurrent_attacks=1`, **Then** the first vectors executed are the ones
   `chain_targeting` chose for the `read_file` to `http_request` chain, and
   `CampaignResult.chain_targets` names that chain with those vector ids and marks them as run.
2. **Given** the same agent whose scripted model calls `http_request` with the file content when
   a chain-targeted prompt arrives, **When** the campaign runs, **Then** the `AttackResult` of
   the first chain-targeted vector carries that `http_request` call as evidence.
3. **Given** an agent with no chains, **When** the campaign runs, **Then** vector order and
   results equal the base branch and the existing scanner tests pass unchanged.

### User Story 2 - Strategies see the chains (Priority: P1)

1. **Given** `AdaptiveStrategy` and a context whose chains target vectors in a phase not yet
   run, **When** `select_next_phase` scores phases, **Then** that phase scores higher than with
   no chains.
2. **Given** `LLMAdaptiveStrategy` and a context with chains, **When** it asks for a phase,
   **Then** the prompt lists each chain's tools and type.

### User Story 3 - Reports show the targets (Priority: P1)

1. **Given** a scan result with chains, **When** the Markdown and HTML reports render, **Then**
   each shows one table of chain, vulnerability type and chosen vector ids.

### User Story 4 - Rendering and fit (Priority: P1)

1. **Given** the `read_file` to `http_request` chain, **When** `chain_targeting` renders a chosen
   vector's prompt, **Then** the prompt names `read_file`, `http_request` and a concrete path,
   and no chosen vector carries a `protocol_filter` that excludes the target.

### User Story 5 - Budget (Priority: P1)

1. **Given** the PR head, **When** `tests/unit/application/test_scanner_size.py` runs, **Then**
   `scanner.py` is at most 750 lines and every sub-module at most 400.

## Requirements *(mandatory)*

- **FR-001**: The scanner runs chain analysis once after discovery and before the first phase.
- **FR-002**: `CampaignContext.dangerous_chains` and `chain_vectors` are filled at every
  construction site.
- **FR-003**: `chain_targeting.plan` maps chains to vectors with the family table, drops
  `harmful_task`, protocol-restricted, multi-turn and PAIR vectors, ranks by fit then severity
  and gives each vector to one chain (the highest-risk chain that can use it), at most
  `MAX_VECTORS_PER_CHAIN` (5) per chain.
- **FR-004**: `chain_targeting.steer` moves a phase's chain-targeted vectors to the front, in
  plan order, replacing each with its rendered copy; other vectors keep their order.
- **FR-005**: `AdaptiveStrategy` adds 0.3 to a phase holding chain-targeted vectors not yet run.
- **FR-006**: `LLMAdaptiveStrategy`'s phase-selection prompt has a `Dangerous tool chains` line.
- **FR-007**: `CampaignResult.chain_targets: list[ChainTarget]` (tools, vulnerability_type,
  vector_ids, ran); Markdown and HTML show it in one table.
- **FR-008**: Rendered prompts name the source tool, the sink tool and the resource.

## Assumptions

- The target's protocol is unknown to the application layer (no adapter exposes it), so only
  vectors with an empty `protocol_filter` are chain-targeted. Overturned when an adapter exposes
  its protocol: pass it to `plan`.
- Multi-turn (`tactic != "single"`) and PAIR vectors are not chain-targeted: the chain task is
  one request, and PAIR vectors are queued last in a phase anyway.
- Five vectors per chain, each vector given to one chain. Overturned if reports show chains
  starved of vectors on large agents.
- `lethal_trifecta` chains match no family in the promise's table, so they get no targets.
  Overturned by adding a row.
- The candidates are the vectors the campaign's phases run at its coverage level, minus
  `exclude_vectors`.

## Success Criteria

- **SC-001**: On the flat agent with a scripted model, the first execution-phase results are the
  chain-targeted vectors and the first carries the `http_request` call.
- **SC-002**: With no chains, run order equals the library order.
- **SC-003**: `scanner.py` at most 750 lines, `phase_executor.py` and `chain_targeting.py` at
  most 400.
