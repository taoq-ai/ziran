# Feature Specification: append sql_query and python_repl to send_email chain patterns

**Feature Branch**: `ziran-dev-patterns`
**Created**: 2026-10-17
**Status**: Active
**Track**: SLICE (two YAML entries, one test class, one docs table; under ten tasks)
**Base**: `develop` @ 2e403cb
**Input**: an agent with `sql_query` and `send_email` gets no chain for that pair from
`ToolChainAnalyzer.analyze(include_cycles=False)`, and neither does an agent with
`python_repl` and `send_email`. Both pairs read or compute data and then email it out. Add one
pattern for each, at the end of `chain_patterns.yaml`.

## The item in my own words

Two dangerous pairs are missing from the pattern library. A tool that runs SQL queries next to a
tool that sends email lets an agent mail database rows to anyone. A Python REPL next to an email
tool lets it mail whatever the code computed or read. With cycle search on, the analyzer hides
this gap on complete graphs, because a cycle through `read_file` and `send_email` lists every
tool on it. With cycle search off, the call the static audit uses, nothing is reported for
either pair.

The change appends exactly two patterns after the last existing one. Nothing existing is added
to, edited or moved. The first matching pattern wins, so a pair that matched before keeps its
type, and these two can only add chains for pairs that matched nothing.

Done means:

1. A graph with `sql_query` and `send_email` gives a `database_exfiltration` chain with cycles
   off; `python_repl` with `send_email` gives `repl_exfiltration`.
2. Compared with `b813e4f`, the pattern list gains exactly these two entries at its end; none
   is removed or reordered.
3. On the ziran-paper dev split with cycles off, chain recall goes from 4 of 10 to 6 of 10
   (gt_ca_tp_006#0 and gt_tc_tp_003#0 now found), measured without loading any held-out
   scenario.

## Study note: these patterns are post-hoc

This change comes from the ziran-paper study's dev-split error analysis
(`study/analysis/dev_fn_analysis.md` in taoq-ai/ziran-paper). The study's corpus data was first
seen on 2026-10-09T08:26:11Z. Under the study's decision D-1 and the owner's answer of
2026-10-17, every pattern, alias or classifier change made after that time is post-hoc. Both
patterns in this spec are post-hoc: corpus findings they produce are reported separately, next
to the study-v1 headline and not inside it. The fix used dev-split scenario ids only. No
held-out scenario file was opened, no ground-truth label changed, and no corpus data was read.

## Current behaviour (read on `develop` @ 2e403cb)

- `ToolChainAnalyzer._match_pattern` (`ziran/application/knowledge_graph/chain_analyzer.py`)
  walks the patterns in file order and returns the first one whose source and target both
  match, by substring or keyword overlap. File order is the registry order.
- The library has 124 patterns. Sources with target `send_email` include `read_file`,
  `database_query`, `search_database` and `sql_database`, but neither `sql_query` nor
  `python_repl` matches any of them: `sql_query` has the keywords `sql` and `query`, which do not
  cover `database`, and `python_repl` shares no keyword with any of them.
- The one `sql_query` pattern targets `execute_code`. The four `python_repl` patterns target
  `requests`, `shell`, `http_request` and `write_file`.
- `canonical_tool_name` leaves `sql_query`, `python_repl` and `send_email` unchanged.
- `database_exfiltration` (from `database_query` to `http_request` and `requests`) and
  `repl_exfiltration` (from `python_repl` to `http_request`) already exist as types.
- On a complete graph over `sql_query`, `python_repl`, `send_email` and `read_file`, the only
  chain with cycles off is `read_file` to `send_email` (`data_exfiltration`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Query and REPL output emailed out is reported (Priority: P1)

A user audits an agent that can run SQL or Python and send email. The audit reports the pair
without relying on cycle search.

**Independent Test**: build an in-memory `AttackKnowledgeGraph` with the two tools linked both
ways and run `ToolChainAnalyzer.analyze(include_cycles=False)`.

**Acceptance Scenarios**:
1. `sql_query` with `send_email` gives exactly one chain, `sql_query` to `send_email`, type
   `database_exfiltration`.
2. `python_repl` with `send_email` gives exactly one chain, `python_repl` to `send_email`, type
   `repl_exfiltration`.

### User Story 2 - Nothing that matched before changes (Priority: P1)

**Acceptance Scenarios**:
1. The two patterns are the last two entries of the registry, in the order above.
2. Compared with `b813e4f`, no pattern is removed, edited or reordered.
3. On the four-tool data-analyst tool set, `read_file` to `send_email` stays
   `data_exfiltration`; the two new pairs are added next to it.

### User Story 3 - Dev-split recall with cycles off (Priority: P2)

**Acceptance Scenarios**:
1. With ziran-paper's dev scoring at the branch head and cycles off, run.py-style recall is
   6 of 10, up from 4 of 10 at `b813e4f` and at `develop` @ 2e403cb.
2. The measurement loads no held-out scenario.

### Edge Cases

- **First match wins.** A tool pair already matched by an earlier pattern keeps that pattern.
  For example `database_query` to `send_email` stays on its own earlier entry.
- **Other tool names.** Matching is by substring or keyword overlap, so ids such as
  `run_sql_query` or `tool_python_repl` paired with an email tool also gain these chains. That
  is the intended reach; it follows the matching every other pattern uses.
- **Expected chain gt_ca_tp_006#1** (`execute_code` then `http_request`) stays a miss: neither
  tool name matches `python_repl` or `send_email` under the scorer, and the agent has no HTTP
  tool. The dev analysis classes it as label suspect; labels are out of scope.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: append `sql_query` to `send_email` (type `database_exfiltration`, risk
  `critical`, category `data_exfiltration`) at the end of `chain_patterns.yaml` (US1.1).
- **FR-002**: append `python_repl` to `send_email` (type `repl_exfiltration`, risk `critical`)
  after it (US1.2).
- **FR-003**: no other pattern is added, edited or moved; no change to `tool_aliases.py`,
  `chain_analyzer.py`, the tool classifier, cycle search or any ground-truth label (US2).
- **FR-004**: `docs/concepts/tool-chains.md` lists both patterns.
- **FR-005**: no new dependency.

### Assumptions

- **Risk `critical` for both.** Every existing `database_exfiltration` and `repl_exfiltration`
  pattern is critical. Overturn: a reviewer rates email as a narrower channel than HTTP.
- **Category of the REPL pattern is `framework_tools`**, the category of the existing
  `repl_exfiltration` pattern (`python_repl` to `http_request`). The item fixes only the type.
  Category does not affect matching or the study's exfiltration class, which is decided by type.
  Overturn: a reviewer wants it under `data_exfiltration` with the SQL pattern.
- **New section comment.** Both entries sit under an "Email Exfiltration (spec 058)" comment at
  the end of the file rather than in the thematic sections, because moving into a section would
  change their position relative to existing patterns. Overturn: none while order decides type.
- **Measurement.** The promise names ziran-paper's `study/scripts/dev_benchmark.py`. Its loader
  parses every scenario file in the three scored categories before it filters to dev ids, so it
  is run as named and also cross-checked by a scratch probe that loads only the dev files and
  scores them with run.py's own graph builder, analyzer call and `_chain_matches`.

## Success Criteria *(mandatory)*

- **SC-001**: the US1 and US2 tests fail on 2e403cb and pass after the change.
- **SC-002**: every existing test passes unchanged.
- **SC-003**: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/` and
  `uv run pytest --cov=ziran` (coverage at least 85%) pass.
- **SC-004**: dev recall with cycles off is 6 of 10 at the branch head (US3).

## Clarifications

### Session 2026-10-17

- Q: Insert the patterns in their thematic sections or append them? A: append. Order decides
  which pattern a pair takes, so appending is the only placement that cannot change the type of
  an existing finding.
- Q: Add an alias so `sql_query` resolves to `database_query`? A: no. Alias changes are out of
  scope, and an alias would also change which existing patterns `sql_query` takes.
- Q: Turn cycle search off in the runner? A: no. Cycles stay as they are; the study fixes the
  producer's call in its pre-registration.
