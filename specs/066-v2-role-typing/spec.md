# Feature Specification: V2 role typing as an added chain class

**Feature Branch**: `feat/066-v2-role-typing`
**Created**: 2026-11-12
**Status**: Active
**Base**: `develop` @ f5ac085
**Input**: plan item G10-CHAIN-PATCH (ziran-paper goal G-11, tier smart). The binding text is
`prereg/patch-protocol.md` in taoq-ai/ziran-paper, sections 2, 4, 5 and 13, with the dev numbers
of section 12 for V2 (D7, D34, D90). Variant V2 is the one the frozen dev probe
(`study/scripts/g10_dev_probe.py` at `f80204a6`, sha256 `34408009...7e78`, registered in section 13)
selected: trace-weighted recall 0.560 (2,015 of 3,598) at a median flagged share of 0.100. Where
the item text and the protocol differ, the protocol wins.

## The item in my own words

study-v1's chain analyzer finds a chain only when a tool pair matches its closed table of 126
patterns. On the dev probe it flags 0 of the 3,598 exploited tool-pair occurrences, because the
AgentDojo tool names are not in the table. This item adds a second way to find a chain: give each
tool roles from the words in its name, and report a chain for a tool that reads data followed by a
tool that sends, executes or does something high-impact.

- (a) One function, `tool_roles(tool_id, override=None)`, gives a tool's roles out of four:
  `source`, `egress`, `exec`, `high_impact`. With an override it returns the override and does not
  read the name. With none it applies the V2 name rules to `canonical_tool_name(tool_id)`.
- (b) The V2 name rules are the probe's: split the name on separators and CamelCase; `source` when
  the first token is a read verb or any token is a source token; each sink role whose word list
  holds a token. The lists are the probe's literals. The probe's `write` role is no V2 sink and is
  not reported.
- (c) `ToolChainAnalyzer(graph, typed=True)` adds a typed chain for each ordered pair (a, b) of
  distinct tools where a has `source` and b has a sink role, one chain per sink role, unless the
  table already reports a chain on exactly (a, b). A typed chain has `typed=True`, its own
  vulnerability type, and evidence naming each tool's roles and where they came from.
- (d) Without `typed=True` the analyzer's output equals study-v1's. With it, every study-v1 chain is
  still reported, with the same type, beside the typed ones. A test shows both on ziran's chain
  fixtures.
- (e) The hybrid's capability classifier, a shipped catalogue, or any caller that knows a tool's
  roles passes them in `role_overrides`. Those win over the name rules. A tool the classifier
  leaves unknown is absent from the overrides, and the name rules type it.
- (f) The source-to-egress type is `typed_data_exfiltration`, which meets the preregistration's
  exfiltration-class rule (`exfil|leak`, section 4 of `prereg/preregistration.md`). The other two,
  `typed_untrusted_execution` and `typed_high_impact_action`, do not.
- `tool_classifier.py`, `refusal.py`, `llm_judge.py` and `claude_code.py` stay byte-identical to
  study-v1. No catalogue entry ships, no model call is made, and deterministic mode passes no
  override. The chain plausibility check is not built here.

My words and the item agree, with one reconciliation (Assumptions 1).

## Acceptance scenarios

1. **Given** the 13 dev-split agents, **when** the patched analyzer runs with cycles off, **then**
   every study-v1 chain is still reported with its type, and typed chains are marked
   (`typed=True`) and counted apart. Measured: 18 study-v1 chains and 22 typed chains; agents with
   a chain go from 2 of 7 safe and 4 of 6 vulnerable to 5 of 7 and 6 of 6, the probe's committed
   `agents_with_chain` for study-v1 and V2.
2. **Given** the merged patch, **when** the contamination check greps its diff for the fresh chain
   set's tool names, **then** there is no hit, and `tool_classifier.py` and `claude_code.py` are
   byte-identical to study-v1. The tests use synthetic names and names from ziran's own fixtures.
3. **Given** this spec, **when** a reader compares it with the probe's results file, **then** the
   built variant is V2, with the same lists (see "V2 lists").
4. **Given** synthetic agents of two read tools, and of a read tool with an outbound tool, **when**
   the analyzer runs, **then** the first yields no typed chain and the second yields one.
5. **Given** a tool whose name holds no verb and an override that marks it an egress sink, **when**
   the analyzer runs on it with a read tool, with and without the override, **then** a typed chain
   is reported only with the override, and its evidence names `override` as that tool's role
   source.

## V2 lists

Verbatim from `g10_dev_probe.py` at `f80204a6`, lines 73 to 89. `READ_VERBS` is the list ziran
already holds in `ziran/application/detectors/provenance.py` (spec 063), imported, not copied.

| List | Role | Words |
| --- | --- | --- |
| `READ_VERBS` | source, as the first token | the 51 words of spec 063 |
| `SOURCE_TOKENS` | source, any token | read query get list search fetch load scan view retrieve download select lookup find show loader browse scrape crawl diff log |
| `EGRESS` | egress | send post publish upload share forward reply notify webhook push export tweet request requests http curl fetch email message invite transfer pay |
| `EXEC` | exec | execute exec run shell bash repl eval command deploy interpreter terminal subprocess |
| `HIGH` | high_impact | transfer pay delete remove grant revoke invite unlock withdraw deploy purchase buy order cancel drop wipe erase kill terminate |

The probe's V2 sink set is `{"egress", "exec", "high"}`; ziran names `high` as `high_impact`, the
capability classifier's field name (protocol section 2).

## Role sources

Each typed chain's `evidence["role_source"]` maps each of its two tools to one of:

| Value | When |
| --- | --- |
| `override` | the caller passed roles for the tool in `role_overrides` |
| `table` | no override, and ziran's alias table (`canonical_tool_name`) mapped the id, so the name rules read the table's name |
| `name_rule` | no override, and the name rules read the id itself |

## Requirements

- **FR-001** `ziran/application/knowledge_graph/role_typing.py` holds `tool_roles` and the V2
  lists; a test pins each list to the probe's literal.
- **FR-002** `tool_roles` with no override equals the probe's `roles(name, canonical_tool_name)`
  restricted to the V2 roles, on every name a seeded test generates.
- **FR-003** An override that is a string, or holds a role outside the four, raises `ValueError`.
- **FR-004** `ToolChainAnalyzer` adds typed chains only with `typed=True`; `role_overrides` without
  it raises `ValueError`.
- **FR-005** With `typed=True` the typed pairs equal the probe's V2 typed pairs minus the pairs the
  table reports, on seeded synthetic agents.
- **FR-006** Without `typed=True` the analyzer's chains on every ground-truth agent and every pattern
  pair equal the study-v1 fixture; with it, the untyped chains still do.
- **FR-007** `DangerousChain.typed` defaults to `False`.

## How this fails

1. Typed chains flag most multi-tool agents, so the patch-only precision guard fails and the corpus
   prevalence saturates. On ziran's scenario-verdict benchmark with typed chains on, false
   positives go from 3 to 18 of 26 true-negative scenarios; this is why they are opt-in.
2. Names cannot show guardrails: on dev, flagged safe agents go from 2 of 7 to 5 of 7.
3. The fresh chain set's verbs differ from the dev verbs, and recall stays under the bar. Of the
   1,583 dev occurrences V2 misses, 920 have a sink verb outside V2; the override is how the
   classifier will type those.

## Assumptions

1. Typed chains are opt-in (`typed=True`), not on by default. Why: on by default they change every
   scan, audit and trace analysis, and the scenario-verdict benchmark's false positives on its
   true-negative scenarios rise from 3 to 18 (measured with `benchmarks/ground_truth/run.py`); the
   item requires that benchmark to keep its true-negative result. With the flag off, no user output
   changes and the benchmark baseline stays as it is. Deterministic mode, the chain set and the
   corpus run pass `typed=True` (paper side). Overturned if the planner wants them on by default:
   flip the default, update two scanner tests, and regenerate the sample SARIF baseline that three CLI tests read.
2. "Write tools count as sources" is met through the override: a write tool the classifier marks
   `reads_untrusted` or `reads_private` gets the source role from its reply. The name rules stay
   the probe's, which give a write verb no source role, because V2 must equal the probe.
   Overturned if the planner means the name rules should give write tools the source role; that
   would be a new variant, not V2, and its dev recall is unmeasured.
3. A typed chain needs no graph edge between its tools, as in the probe and `chainset.py`, which
   pair every tool of an agent. Overturned if a scan graph should limit typed chains to reachable
   pairs.
4. A pair the table reports on exactly (a, b) is not typed again, so a pair is counted once, as
   the probe's `study-v1 or typed` union does. Cycle chains do not count for this, so the typed set
   is the same with cycles on and off.
5. Typed chains have risk level `high`, below the table's `critical` exfiltration patterns, as the
   roles come from names alone.
6. The catalogue role source is not a separate value here: this item ships no catalogue, and a
   catalogue's roles come in through `role_overrides` and read `override`. The item that ships a
   catalogue can split the label.
