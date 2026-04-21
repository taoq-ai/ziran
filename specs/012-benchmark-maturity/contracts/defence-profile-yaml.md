# Contract: Defence Profile YAML Schema

**Applies to**: Files supplied via `ziran scan --defence-profile <file>` or inlined under a `defence_profile:` key in the main scan config.

## Schema

```yaml
# profile.yaml — standalone profile file
name: prod-ingress-v1
defences:
  - kind: input_filter
    identifier: nemo-guardrails@v0.8
    evaluable: false
  - kind: output_guard
    identifier: lakera-guard@2025-09
    evaluable: false
  - kind: hybrid
    identifier: custom-internal-regex
    evaluable: false
```

Or inlined under the scan config:

```yaml
# scan-config.yaml (existing file — new key added)
target: …
phases: [discovery, execution, escalation]
defence_profile:
  name: prod-ingress-v1
  defences:
    - kind: input_filter
      identifier: nemo-guardrails@v0.8
      evaluable: false
```

## Rules

| Rule | Enforcement |
|---|---|
| `name` required, non-empty string | Pydantic validation |
| `defences` is a list (possibly empty) | Pydantic validation |
| Each `kind` is one of `input_filter`, `output_guard`, `hybrid` | Pydantic `Literal` type |
| Each `identifier` is a non-empty string | Pydantic validation |
| Each `evaluable` is a boolean, default `False` | Pydantic default |
| Empty `defences` list produces no `evasion_rate` in the campaign report | Application-layer invariant (FR-017) |
| Profile with no `evaluable: true` entries produces no `evasion_rate` | Application-layer invariant |

## CLI UX

```text
ziran scan --target <agent> --defence-profile ./profiles/prod-ingress.yaml
```

If both `--defence-profile` and a `defence_profile:` key in scan config are provided, the flag wins and a warning is logged.

## Report surface

When a profile is declared, the campaign report (JSON, Markdown, HTML) includes:

1. A "Declared defences" section listing each declaration (kind, identifier, evaluable flag).
2. An `evasion_rate` value — or, if no declaration was `evaluable`, the string `"not computable"` alongside the declared defences (rather than a numeric field) in Markdown/HTML. The JSON omits `evasion_rate` entirely in the not-computable case (FR-017, determinism).

When no profile is declared (or the profile is empty), the report contains **zero** defence or evasion content — byte-identical to a pre-release report.
