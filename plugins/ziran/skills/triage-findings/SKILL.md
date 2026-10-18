---
name: triage-findings
description: Triage a ZIRAN scan result (campaign_*_report.json) - read the findings, decide fix or accept for each, write justified entries in .ziran/suppressions.yaml, gate CI with `ziran ci`, and produce SARIF, guardrail policies or proof-of-concept scripts. Use when the user has a ZIRAN result file, a failing `ziran ci` gate, asks what a finding means, or wants to suppress, export or reproduce findings.
---

# Triage ZIRAN findings

A scan result lists successful attacks and dangerous tool chains. The CLI can render it, gate on
it and turn it into artifacts. You add the judgement: which findings are exploitable for this
agent, what the fix is, and, for the few that are accepted, a suppression whose reason a
reviewer can check.

Needs `ziran>=0.42.0` (`ziran --version`). The result file is usually
`<output>/campaign_<id>_report.json` from `ziran scan`.

## 1. Read the result

```bash
ziran report <result.json> --format json
```

`--format markdown` or `html` gives a shareable report. From the JSON, list per finding: kind
(attack or chain), id (`vector_id` or `vulnerability_type`), severity, and the evidence (the
prompt, the response, and `tool_calls` for attacks; the tool path for chains). For a chain, give
its ATLAS techniques from
[atlas-chains.md](../threat-model-agent/references/atlas-chains.md).

## 2. Decide fix or accept

Default to fix. Accept only when the user names a control that makes the finding harmless here
(the output is sandboxed, the tool is behind human approval, the data is public). An attack whose
evidence shows a dangerous `tool_calls` entry is not acceptable because the text reply refused:
the tool ran. Fixes follow the chain table's "Narrowest fix" column or remove the tool the attack
used.

## 3. Gate and get fingerprints

```bash
ziran ci <result.json> --suppressions .ziran/suppressions.yaml --sarif ziran.sarif
```

`ziran ci` exits `1` when the gate fails and `2` on a usage error (for example a
`--suppressions` path that does not exist). Fingerprints are printed only when a suppressions file
is loaded, so bootstrap an empty one first:

```yaml
version: 1
entries: []
```

The output then lists `new attack <id> [<severity>] fingerprint=<64 hex> content_hash=<64 hex>`
per unsuppressed finding.

## 4. Write a suppression for each accepted finding

Use this template, one entry per accepted fingerprint and content hash:

```yaml
version: 1
entries:
  - fingerprint: <fingerprint printed by ziran ci>
    content_hash: <content_hash printed by ziran ci>
    reason: "<the control that makes this harmless, and the ticket or review that accepted it>"
    added_by: <team or person who accepted it>
    expires: <YYYY-MM-DD, 90 days out at most>
```

Rules: `reason` and `added_by` are required and unknown keys are rejected. Write a reason a
reviewer can verify ("output rendered in a sandboxed iframe, SEC-123"), never "false positive" or
"accepted". Always set `expires`. If the severity, chain tools or chain risk changes later, the
entry stops matching and the gate fails with `suppression_regressed`; an expired entry fails with
`suppression_expired`. Re-run step 3 and confirm the summary line shows the expected
`suppressed` count.

The GitHub Action runs `ziran ci` in the workspace root, so a committed
`.ziran/suppressions.yaml` is picked up there too.

## 5. Artifacts on request

Runtime guardrail policies from the chains (formats `rego`, `cedar`, `nemo`, `invariant`):

```bash
ziran export-policy --result <result.json> --format rego --out policies --severity-floor high
```

Proof-of-concept scripts to reproduce confirmed attacks (format `python`, `curl`, `markdown` or
`all`):

```bash
ziran poc <result.json> --format python -o pocs
```

PoC scripts send real attack prompts to the target: tell the user to run them only against an
agent they are authorised to test.
