# Contract: Benchmark Coverage Reports

**Applies to**: `benchmarks/atlas_coverage.py` (new) and the extensions to `benchmarks/benchmark_comparison.py`, `benchmarks/owasp_coverage.py`, `benchmarks/generate_all.py`, `benchmarks/inventory.py`.

## `benchmarks/atlas_coverage.py`

New script paralleling `owasp_coverage.py`.

### CLI

```text
$ uv run python benchmarks/atlas_coverage.py
$ uv run python benchmarks/atlas_coverage.py --json benchmarks/results/atlas_coverage.json
```

### JSON output schema

```json
{
  "generated_at": "2026-04-21T10:30:00Z",
  "snapshot_date": "2025-10-01",
  "totals": {
    "vectors_total": 612,
    "vectors_with_atlas_mapping": 612,
    "vectors_without_atlas_mapping": 0,
    "techniques_covered": 63,
    "techniques_total_in_enum": 66,
    "agent_specific_covered": 14,
    "agent_specific_total": 14
  },
  "per_tactic": {
    "AML.TA0002": {
      "tactic_name": "Reconnaissance",
      "techniques_covered": 3,
      "techniques_total": 5,
      "vector_count": 28
    }
  },
  "per_technique": {
    "AML.T0051": {
      "name": "LLM Prompt Injection",
      "tactic": "AML.TA0008",
      "agent_specific": false,
      "vector_count": 175
    }
  },
  "uncovered_techniques": ["AML.T0040", "AML.T0041", "AML.T0042"],
  "uncovered_agent_specific": []
}
```

### Exit code

| Condition | Exit code |
|---|---|
| All validation passes (every vector mapped, all 14 agent-specific techniques covered, ≥ 60 techniques total) | 0 |
| Any vector has empty `atlas_mapping` | 1 (with list of offending vector IDs) |
| < 14 agent-specific techniques covered | 1 (with list of missing) |
| < 60 techniques covered overall | 1 (warning, not strict error — behind `--strict` flag the same condition fails) |

### Determinism

- Running the script twice without library changes produces byte-identical JSON (sorted keys, sorted arrays).
- Stdout table uses the same sorted order.

## Changes to `owasp_coverage.py`

- Remove `_PLANNED_ISSUES` entries for `"LLM05"` and `"LLM10"` once coverage is achieved.
- Add a strict assertion: every category has `_STRONG` or `_COMPREHENSIVE` status, otherwise exit 1. Behind a `--strict` flag if existing consumers rely on non-strict behaviour; otherwise default to strict since all gaps are intended to be closed in this release.

## Changes to `benchmark_comparison.py`

- Add a MITRE ATLAS row summarising technique coverage (denominator = `len(AtlasTechnique)`, numerator = covered in library).
- Update TensorTrust, WildJailbreak, ToolEmu, CyberSecEval rows to reflect new vector counts after Phase 5.
- Add a RAG injection row pointing to the new `rag_poisoning.yaml` (replaces the "Not yet implemented" LLMail-Inject row).

## Changes to `generate_all.py`

- Invoke `atlas_coverage.py` in the regeneration list alongside `owasp_coverage.py`.
- Regeneration MUST be idempotent: running twice produces byte-identical outputs.

## Changes to `docs/reference/benchmarks/coverage-comparison.md`

- Regenerated — no manual edits. The regeneration script must produce this file in one pass from the library state.

## Contract tests

Tests in `tests/integration/test_atlas_coverage_script.py`:

1. Running the script with `--json /tmp/out.json` writes a file matching the schema above.
2. Running the script twice produces byte-identical JSON.
3. When a vector has empty `atlas_mapping`, the script exits non-zero and names the vector in stdout.
4. When a library snapshot has all coverage, the script exits zero.
