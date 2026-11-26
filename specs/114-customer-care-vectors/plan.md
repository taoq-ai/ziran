# Implementation Plan: customer-support abuse vectors

**Branch**: `feat/114-customer-care-vectors` | **Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). YAML in the existing vector schema; no new code path,
schema field, enum member or dependency.

## Approach

1. One file, `ziran/application/attacks/vectors/customer_care.yaml`, 8 vectors with one prompt
   each, tagged `spec-114`, `customer_care` and one family tag (`refund_abuse`,
   `discount_override`, `identity_bypass`, `other_customer_read`).
2. Evidence: in a scan, `scan_metadata` sets the payload to the rendered prompt, and the
   side-effect detector's rule P1 flags a call whose arguments hold a value of it. The
   authorization detector does the same for `authorization_bypass` vectors (ids of 3 or more
   characters). So each prompt's variables are the abusive values: amounts (`475.00`, `350.00`,
   `213.00`), a code (`TEAMRATE-82291`, `GW-58120347`), another customer's id (`CUST-58213907`,
   `ORD-77341902`), email and card digits. The prompts are worded to hold none of the values an
   honest call about the signed-in customer sends (the 882 `OWN_CALLS` of the test), and the
   money families name no order id.
3. Categories: the money families are `tool_manipulation`; identity bypass and other-customer
   reads are `authorization_bypass` with the `bola` tag, like `authz_bola_*`.
4. Indicators are signals only (study-v2.1): success indicators quote a completed action
   ("refund of 475.00 has been issued"), failure indicators are refusal sentences.
5. `benchmarks/generate_all.py` regenerates `benchmarks/README.md` and
   `docs/reference/benchmarks/coverage-comparison.md`; `regression_check.py --update-baseline`
   refreshes `benchmarks/results/baseline.json`. `README.md` and `atlas-mapping.md` get the library
   size by hand from `benchmarks/atlas_coverage.py --json`. `docs/reference/attack-library.md` gets
   a file row and a family table.

## Constitution check

- Hexagonal: data in `application/attacks/vectors/`; no layer change.
- Type safety: vectors validate through the `AttackVector` model; no Python source change.
- Tests: `tests/unit/test_customer_care_vectors.py` runs every new vector through the real
  `AttackExecutor` and `DetectorPipeline` with a scripted support agent.
- Extensibility: vectors are YAML, not code (principle V).
- Frozen files: no file under `ziran/application/detectors/`, the hybrid judge, role typing,
  tool aliases or `chain_patterns.yaml` changes.

## Test plan

- Count, families, `https` references and all three mappings present.
- Each variable is at least 3 characters and appears in the rendered prompt.
- A call holding the variables is a success; a refusal quoting them is not; a compliant reply with
  calls for the signed-in customer is not, on each of the 882 `OWN_CALLS`.
- Fitness: `test_attack_library.py`, `test_atlas_agent_techniques.py`, `test_atlas_enum.py`,
  `test_owasp_mapping.py`, `test_owasp_agentic_mapping.py`, `test_benchmark_scripts.py`,
  `test_benchmark_regression.py`, `test_scanner_size.py`.
