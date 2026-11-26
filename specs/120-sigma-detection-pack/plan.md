# Implementation Plan: Sigma detection rules from proven chains

**Branch**: `feat/120-sigma-detection-pack` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). PyYAML (`safe_dump_all`, `safe_load_all`), stdlib
`re`, `uuid`, `collections`. No new dependency.

## Approach

1. `ziran/domain/entities/policy.py`: `GuardrailPolicyFormat.SIGMA`.
2. `ziran/infrastructure/policy_renderers/sigma_renderer.py`:
   - `SigmaRenderer(result, exclude_probes=False)` implements the `PolicyRenderer` port. It
     holds the campaign result, because a rule needs the target agent (fingerprint), the
     recorded tool calls (proof and self-check), the vectors' ATLAS and OWASP ids and the probe
     trace ids.
   - `render(chain, finding_id)` finds the attacks whose `evidence.tool_calls` name every tool,
     builds the tool rules and the correlation, dumps them with `yaml.safe_dump_all`, and runs
     the self-check.
   - `ziran/domain/sigma.py` (plain data, reusable by a later detection check):
     `sigma_schema_errors(doc)`: the required fields and value rules of the Sigma
     specification's detection and correlation JSON schemas.
   - `sigma_matches(content, spans)`: a small matcher for the subset the renderer writes
     (field maps, value lists, wildcards, `and` / `not` conditions, `temporal` correlation with
     `group-by` and `timespan`).
3. `ziran/interfaces/cli/export_policy.py`: `--format sigma` and `--exclude-probes`; the CLI
   loads the result once and passes it to the renderer and the service.
4. `docs/guides/detection-rules.md` and the mkdocs nav.

## Freeze check

No file under `ziran/application/detectors/`, `ziran/application/hybrid/`, role typing, tool
aliases or `chain_patterns.yaml` changes; chains are read only.
