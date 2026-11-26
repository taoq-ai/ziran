# Feature Specification: policy export escapes tool names and emits OPA 1.0 Rego

**Feature Branch**: `fix/107-policy-export-escaping`
**Created**: 2026-11-26
**Status**: Active
**Plan item**: E-POLICY-OPA1 (goal G-f)

## The promise in our own words

`ziran export-policy` turns dangerous tool chains into guardrail policies in four languages:
Rego, Cedar, Colang and Invariant. Each renderer in `ziran/infrastructure/policy_renderers/`
pastes the scanned tool names, the finding id and the vulnerability type into the policy text
as they came. A tool name holding a double quote and a newline closes the string and starts a
new rule, so a scanned agent can write policy for the operator (CWE-74). The Rego renderer also
emits `deny[msg] {`, which OPA 1.x refuses to load.

After the fix every value placed in policy text is escaped for the language it lands in:

- Rego and Invariant strings: JSON string literals (`json.dumps`, ASCII, so U+2028 and U+2029
  are escaped too).
- Colang strings: the same JSON literal, which escapes the quote and the backslash and keeps
  controls off the line.
- Cedar strings and entity ids: Cedar's escapes, `\"` and `\\`, with every non-printable
  character as `\u{..}`.
- Comment lines: the value goes through `printable` from `ziran/domain/text.py`, so C0, DEL,
  C1, U+2028 and U+2029 show backslash-escaped and no value starts a new line.

The Rego module moves to OPA 1.0 syntax: `package ziran.guardrails`, `import rego.v1`,
`deny contains msg if { ... }`. It loads in OPA 1.x, and in OPA 0.x from 0.59.

Cedar keeps its two-tool limit and its skip reason.

## Acceptance scenarios

1. Given a chain `[read_file, http_request]`, when Rego is exported, then `opa check` with
   OPA 1.x accepts the module, and `opa eval` of `data.ziran.guardrails.deny` on a matching
   trace returns one message.
2. Given a chain whose second tool name holds a double quote, a newline, a closing brace and a
   whole `deny contains "pwned" if { true }` rule, when Rego is exported, then `opa check`
   passes, `opa parse` shows exactly one deny rule, and its tool term equals that name.
3. Given the same hostile two-tool chain, when Cedar is exported, then cedarpy parses exactly
   one forbid policy whose resource id equals the hostile name.
4. Given a tool name holding U+2028 or a newline, when any of the four formats is exported,
   then no text of that name after the separator lands on a line outside a string literal.
5. Given CI on the PR, when the test job runs on 3.11, 3.12 and 3.13, then the opa tests run,
   not skipped, and pass.

## Out of scope

Cedar chains of three or more tools, AgentCore schema validation, new formats, export CLI
options.

## Assumptions

- The owner's decision names `ziran/application/policy_export`; the renderers it calls live in
  `ziran/infrastructure/policy_renderers/`, so the fix lands there and the export service is
  unchanged. Overturned if the owner wants the escaping in the service.
- Colang 2.0 string literals accept JSON's `\uXXXX` escapes as Python literals do. No Colang
  parser is installed here, so the tests decode the literal with `ast.literal_eval`.
  Overturned by a NeMo Guardrails parse that rejects `\u` escapes.
- `json.dumps` writes a character above U+FFFF as a surrogate pair. OPA decodes the pair to the
  one character; `ast.literal_eval` would not. Scanned tool names outside the BMP are left as a
  known limit for Invariant and Colang.
- The opa tests skip without the binary locally and fail when `CI` is set, so `release.yml`,
  which runs the unit tests too, installs OPA beside `test.yml`.
