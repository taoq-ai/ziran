# Sigma Detection Rules

`ziran export-policy --format sigma` turns each proven dangerous tool chain of a scan into
[Sigma](https://sigmahq.io/) rules over OpenTelemetry GenAI tool spans. A security operations
team converts them with a pySigma backend (Splunk, Elastic, Microsoft Sentinel and others) and
deploys them where the agent's traces land.

```bash
ziran export-policy --result reports/campaign_report.json --format sigma --out rules/
```

The command writes one `.yml` file per chain, named after the finding id.

## Which chains get rules

Only proven chains. A chain is proven when one recorded attack of the scan called every tool of
the chain (the attack's `evidence.tool_calls`). A chain the graph found but no attack ran is
skipped; `--verbose` prints the reason. `--severity-floor` applies as for the other formats.

## What a file holds

For a chain of two or more tools, one rule per tool and one correlation rule:

- **Tool rules** match an `execute_tool` span that names the tool, as the
  [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
  define it: `gen_ai.operation.name: execute_tool` and `gen_ai.tool.name`. A tool id with the
  `tool_` prefix matches the bare name too. Their level is `informational`: a lone `read_file`
  is not an alert.
- **The correlation rule** is a Sigma `temporal` correlation over the tool rules, grouped by
  `gen_ai.conversation.id` within one hour. It carries the chain's severity as its level.

A one-tool chain (for example an unscoped shell tool) gets a single rule at the chain's level.

Every rule carries:

| Field | Value |
|---|---|
| `id` | A UUID derived from the finding fingerprint and the tools, stable across re-exports |
| `references` | `ziran finding <id>`, `ziran fingerprint <sha256>`, `ziran vector <id>` per proving vector |
| `tags` | The proving vectors' MITRE ATLAS ids (`atlas.aml.t0086`) and OWASP ids (`owasp.llm02`, `owasp.asi02`) |
| `level` | From the chain's severity: `critical`, `high`, `medium` or `low` |
| `falsepositives` | The benign use the rule can also match |
| `status` | `experimental` |

The fingerprint is the one `ziran ci` suppressions use, so an alert, a suppression entry and
the scan finding all join on one value.

## Ordered matches

The correlation is unordered: it fires when every tool of the chain appears in one session
within the timespan, in any order. Sigma's `temporal_ordered` type would keep the order, but
only the SQLite backend implements it, so a Splunk or Elastic conversion would fail. For an
ordered match, write the native query: Splunk `transaction` or `streamstats`, Elastic EQL
`sequence`.

## Mapping fields to your pipeline

The rules use the OpenTelemetry attribute names. When your SIEM stores spans under other names
(for example ECS `trace.id`, or a session id other than `gen_ai.conversation.id`), map them in a
pySigma processing pipeline, or edit the `group-by` field and the timespan in the file.

## Leaving out scan traffic

With `--exclude-probes`, every tool rule gets a filter on the trace ids of the scan's own
requests:

```yaml
detection:
  selection:
    gen_ai.operation.name: execute_tool
    gen_ai.tool.name:
    - read_file
  filter_ziran_probe:
    trace_id:
    - 4bf92f3577b34da6a3ce929d0e0e4736
  condition: selection and not filter_ziran_probe
```

The trace ids come from the scan's probe markers, so the target needs `probe_markers:
traceparent` or `both` (see [Remote Agents](remote-agents.md)); `header` alone sends no trace
id. A caller controls the `traceparent` header, so anyone who knows a scan's trace id can send
it to slip past the filter. Use the filtered rules during the test window only.

## Self-check

Before a file is written, the exporter checks every rule in it:

1. Each rule meets the required fields and value rules of the Sigma specification's detection
   and correlation JSON schemas (title length, UUID id, level and status names, tag format,
   log source, condition, correlation type, rules, `group-by` and timespan).
2. The proving attack's recorded tool calls, replayed as `execute_tool` spans of one session,
   match the file's top rule.
3. The same session without the chain's last tool does not match it.

A chain whose rules fail is skipped with the reason, never written. The first comment line of
each file names the vector whose calls the check replayed.

## Converting

With [sigma-cli](https://github.com/SigmaHQ/sigma-cli) and a backend:

```bash
pip install sigma-cli pysigma-backend-splunk
sigma convert -t splunk --without-pipeline rules/
```

`--without-pipeline` keeps the OpenTelemetry field names; name a pipeline instead to map them.
The correlation converts to a Splunk `multisearch` with `stats dc(event_type)` per session and
hour. The tool rules are not converted on their own: a correlation leaves them out unless you
set `generate: true`.
