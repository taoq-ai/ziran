# Feature Specification: every dangerous chain in the scan SARIF

**Feature Branch**: `feat/092-chain-sarif`
**Created**: 2026-11-23
**Status**: Active
**Plan item**: A-CHAIN-SARIF (goal G-a).
**Base**: `develop` @ eee3253 (specs 086, 088 and 091 slice 1 merged).

## The promise in our own words

`ziran ci` fails the gate on every dangerous tool chain in `CampaignResult.dangerous_tool_chains`,
but `generate_sarif` writes only the direct `lethal_trifecta` (`LT001`). A reviewer in code
scanning cannot see the `data_exfiltration`, `rce` or delegated trifecta chains that failed the
build.

After this change `generate_sarif` writes one SARIF result for every chain:

1. `lethal_trifecta` keeps rule `LT001`. `lethal_trifecta_delegated` gets its own rule `LT002`
   beside it.
2. Every other type shares one rule, `CC001`, the id `ziran audit` already uses for its chain
   rows, with the type in `properties.vulnerability_type`.
3. Each result's `level` comes from the chain's `risk_level` (critical and high: `error`, medium:
   `warning`, low: `note`). Its properties hold `tools`, `vulnerability_type`, and `agent` (plus
   `agents` for a delegated trifecta) when the chain's evidence names them.
4. A result carries `suppressions` exactly when the gate marks that chain suppressed
   (`GateResult.suppressed_chains`), as spec 046 FR-010 does for attacks.

## User Scenarios & Testing

### User Story 1 - A delegated trifecta reaches code scanning (P1)

1. **Given** a scan where `reader` (private data, untrusted content) delegates to `mailer`
   (egress), **When** SARIF is generated, **Then** it has an `LT002` result with level `error`,
   `agent` `reader`, `agents` `[reader, mailer]` and the two tools, and no `LT001` result.

### User Story 2 - A pair chain reaches code scanning (P1)

1. **Given** a `data_exfiltration` chain over `read_file -> http_request`, **When** SARIF is
   generated, **Then** it has a `CC001` result with that type, those tools and the level of its
   risk.

### User Story 3 - Suppressions follow the gate (P1)

1. **Given** two chains and a suppressions file that suppresses the first, **Then** only the
   first result carries `suppressions`.
2. **Given** an entry with the wrong content hash, or an expired entry, **Then** no chain result
   carries `suppressions`.
3. **Given** a suppressed attack at `attack_results[0]` and a chain at
   `dangerous_tool_chains[0]`, **Then** the chain result carries no `suppressions`.

### Edge cases

- A flat agent of 100 tools (spec 086's co-resident cap): 2,501 chains, 2,501 results.
- Tool names with quotes, newlines or `::error::`: the JSON encoder escapes them; message text is
  SARIF plain text, not markdown.
- An unknown `risk_level`: the result is `warning`, as attack results already default.

## Requirements

- **FR-001**: `generate_sarif` emits one result per entry of `dangerous_tool_chains`, after the
  attack results, in chain order.
- **FR-002**: Rule ids: `LT001` for `lethal_trifecta`, `LT002` (`trifecta.DELEGATED_RULE_ID`)
  for `lethal_trifecta_delegated`, `CC001` (`sarif.CHAIN_RULE_ID`) for every other type. Each rule
  appears once, in first-seen order, after the attack rules. `CC001`'s default level and
  `security-severity` are those of the highest risk seen; `LT001` and `LT002` stay at `error`,
  9.0.
- **FR-003**: Each chain result has `level` from `risk_level`, `properties.tools`,
  `properties.vulnerability_type`, and `properties.agent` / `properties.agents` when present in
  the evidence.
- **FR-004**: Each chain result has `partialFingerprints["ziranChain/v1"]`, the SHA-256 of its
  type, agent and tools, so code scanning keeps two chains at the one `agent-under-test`
  location apart. It is stable across runs.
- **FR-005**: A chain result carries `suppressions: [{"kind": "external", "justification":
  <reason>}]` iff `GateResult.suppressed_chains()` holds its index.
- **FR-006**: Output is linear in the chain count: no per-result work beyond the chain itself.

## Sizing

A flat agent of 100 tools (`read_file_0..49`, `http_request_0..49`) through
`import_adapter_structure` and `ToolChainAnalyzer.analyze`, then `generate_sarif`:

| Chains | Results | Rules | SARIF (indent 2) | Per result | `generate_sarif` |
|--------|---------|-------|------------------|------------|------------------|
| 2,501 (2,500 `data_exfiltration`, 1 trifecta) | 2,501 | `CC001`, `LT001` | 2.02 MB | 806 bytes | 9 ms |

GitHub code scanning accepts 25,000 results per run and a 10 MB compressed upload, so the
co-resident cap keeps a flat agent's SARIF far below both.

## Assumptions

- One shared `CC001` rule for the pair-chain types, with the type in properties, not a rule per
  type. Why: `ziran audit` already reports every non-trifecta chain as `CC001`, and spec 088 set
  the precedent of one rule id across audit, scan and CI. Overturned by: a need to filter or
  dismiss by type in code scanning's rule list.
- Every chain is listed; no cap per rule. Why: the gate counts each chain, and a cap would hide
  chains that fail the build, which is the gap this item closes. The 100-tool co-resident cap
  already bounds a flat agent at about 2,500 chains (table above). Overturned by: SARIF near
  GitHub's 25,000-result limit, after which results can be grouped per rule with counts.
- `partialFingerprints` is added to chain results only. Why: all results share the location
  `agent-under-test`, which is no file GitHub can hash, so without a fingerprint same-rule
  chains could merge into one alert. Attack results keep their shape (spec 046 FR-010: nothing
  else changes). Overturned by: code scanning evidence that attack results merge too.
- The `LT001` result gains `properties.vulnerability_type` and `partialFingerprints`, both
  additive. Its message and other properties are unchanged, so the spec 088 tests stand.
- Spec 088's note that the delegated chain does not reach the scan SARIF is superseded here.
  `ziran audit` still has no delegated rows (its agents have no delegation edges).
- Blast radius slice 2 adds properties later: `_chain_result` builds one `properties` dict, so a
  new key is one line.
