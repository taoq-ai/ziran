# Feature Specification: Sigma detection rules from proven chains

**Feature Branch**: `feat/120-sigma-detection-pack`
**Created**: 2026-11-26
**Status**: Draft
**Input**: plan item F-DETECTION-PACK. ZIRAN ships no detection content today
(`git grep -i "sigma\|splunk\|kql" ziran/` finds nothing). `ziran export-policy` renders
findings into guardrail policies (Rego, Cedar, Colang, Invariant), not into rules a security
operations team deploys in its SIEM.

## The item in my words

1. `ziran export-policy --format sigma` writes one Sigma YAML file per proven dangerous tool
   chain. A chain is proven when one recorded attack of the scan called every tool of the chain.
   A chain no recorded attack exercised is skipped, with the reason.
2. Each file holds one single-event rule per tool of the chain over OpenTelemetry GenAI
   `execute_tool` spans (`gen_ai.operation.name: execute_tool`, `gen_ai.tool.name`), and, for a
   chain of two or more tools, one `temporal` correlation rule that fires when every tool rule
   matches in one session (`gen_ai.conversation.id`) within a timespan.
3. Every rule carries the finding id, the finding fingerprint (the same one `ziran ci`
   suppressions use), the proving vectors, ATLAS and OWASP tags from those vectors, a level
   from the chain's severity, and false positives. The correlation's description says that it
   is unordered (Sigma `temporal_ordered` runs only on SQLite backends) and that an ordered
   match needs native SPL or ES|QL.
4. `--exclude-probes` adds a filter on the scan's own probe trace ids (spec 117 markers), so
   replayed scan traffic does not alert.
5. A self-check runs on every rule before it is written: the rule passes the Sigma
   specification's structural rules, matches the proving attack's recorded tool calls when
   they are replayed as spans, and does not match that session with the chain's last tool
   removed. A rule that fails is skipped, never written.

**Acceptance (the item's).**

- Given a scan with a proven `read_file` then `http_request` exfiltration chain, when it is
  exported as Sigma, then the YAML validates against the Sigma schema and its correlation rule
  names both tool rules and the fingerprint.
- Given the exported rules and the chain's own recorded tool calls as OTel spans, when the
  self-check runs, then the correlation matches that session and does not match a session with
  only `read_file`.

In my words, as tests on the real `ExportService`, `SigmaRenderer` and CLI:

- A result with one attack whose recorded calls are `read_file` then `http_request`, and that
  chain, exports three YAML documents. Each passes `sigma_schema_errors` with no error; the
  correlation's `rules` are the two tool rules' names and its `references` hold the fingerprint
  `chain_fingerprint(target_agent, "data_exfiltration")`.
- `sigma_matches` on those rules is true for the recorded calls as spans and false for a
  session with only `read_file`.

## Requirements

- **FR-001**: `GuardrailPolicyFormat.SIGMA` and `--format sigma`, file extension `.yml`.
- **FR-002**: One file per proven chain at or above the severity floor; an unproven chain is a
  skipped policy with a reason.
- **FR-003**: Rule ids are stable UUIDs (uuid5 of fingerprint, tools and step), so a re-export
  of the same chain keeps its ids; the output holds no date or other run-time value.
- **FR-004**: A tool id with the `tool_` prefix matches both the id and the bare name, as the
  blast radius does; Sigma wildcards (`*`, `?`) and backslashes in a tool name are escaped.
- **FR-005**: Target-supplied text (tool names, descriptions) reaches the file only through the
  YAML emitter or `printable`, so it cannot add a key, a document or a comment line.
- **FR-005a**: With `--exclude-probes`, every probe trace id must be 32 lowercase hex digits
  (spec 117); any other value skips every chain with the reason. The ids are escaped anyway, and
  the matcher runs in O(pattern x value), so a hostile pattern cannot stall the self-check.
- **FR-006**: No new runtime dependency. Schema validation is structural, from the Sigma
  specification's JSON schemas; no pySigma (it pulls native `google-re2` and `jq`).
- **FR-007**: No change to detectors, the hybrid judge, role typing, tool aliases, chain
  patterns or study refs.

## Out of scope

- Converting rules to Splunk, Elastic or Sentinel queries (a pySigma backend does that).
- ATT&CK tags: chains carry no ATT&CK mapping; ATLAS ids stand in.
- The `export-policy` composite Action's format list.

## Assumptions

- "Proven" means the tools ran in one recorded attack, successful or not, as the blast
  radius's "demonstrated" does. Overturned if only successful attacks should count.
- Session grouping uses `gen_ai.conversation.id` and a 1 hour timespan. A team maps its own
  session field through a pySigma pipeline or edits the rule. Overturned if the owner wants the
  trace id.
- Tool rules have level `informational` when a correlation carries the chain's level, so a
  backend that generates them alone does not page on a benign `read_file`. A one-tool chain's
  rule carries the chain's level.
- `--exclude-probes` is opt-in: `traceparent` is client-controlled, so a deployed rule that
  trusts it can be evaded by a caller who sends a scan's trace id.
