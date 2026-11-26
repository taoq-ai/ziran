# Feature Specification: `ziran scan --attacker-model`

**Feature Branch**: `feat/127-scan-attacker-flag`
**Created**: 2026-11-27
**Status**: Draft
**Input**: plan item F-SCAN-ATTACKER-FLAG (goal G-f, tier standard). Closes the spec 081 gap the
arch gate named on #598: attacker-driven vectors (`tactic: pair`) run only from the Python API.

## The item in my words

A `tactic: pair` vector needs an attacker LLM that rewrites the prompt each iteration. Today only
a Python caller can give the scanner one (`attacker_llm_client`), so `ziran scan` cannot run the
PAIR loop at all, and it records such a vector as an error. `ziran scan --attacker-model <litellm
id>` builds the attacker client through the same `create_llm_client` / `BaseLLMClient` seam the
judge uses (same provider routing, same key environment variables, same rate and retry flags), and
hands it to the scanner unwrapped, so PAIR records its tokens under the `attacker` stage and the
campaign token and cost caps (spec 047) stop it. The `llm` extra stays optional: asking for an
attacker without it is a clear CLI error. Without the flag, a PAIR vector is not run: it is dropped
before the phase, the target is never called, and one warning line in the report lists it as not
run. It is never an unmeasured result, so it does not turn the scan INCOMPLETE.

**Acceptance, in my words.**

1. A scan with a `tactic: pair` vector and `--attacker-model m` runs the PAIR loop: the attacker
   client gets called, the target gets the attacker's prompts, and the report row carries the
   `pair` evidence (stop reason, iterations, `attacker_model: m`).
2. The same scan without `--attacker-model` has no row for the vector, the target is not called,
   the report's `warnings` name the vector as not run, and `unmeasured_vectors` does not hold it.

## Requirements

- **FR-001** `ziran scan --attacker-model <id>` builds the attacker with `create_llm_client`
  (provider `--llm-provider` or `litellm`, model `<id>`, the `--llm-rpm`, `--llm-tpm` and
  `--llm-max-retries` values) and passes it as `attacker_llm_client`, unwrapped.
- **FR-002** When the `llm` extra is missing, the scan exits 1 with a message that names the flag
  and the extra.
- **FR-003** With no attacker client (CLI or Python), each phase drops its `tactic: pair` vectors
  and adds one warning line that lists their ids as not run. The vectors get no result row.
- **FR-004** Attacker tokens reach the campaign ledger under `attacker`; `--max-cost` checks the
  attacker model's price and does not warn "cannot trigger" when only an attacker is configured.
- **FR-005** `ziran scan` prints the result warnings on the console, so the not-run line is
  visible without opening the report.

## Out of scope

- The dry run (`--dry-run`) still counts PAIR vectors in its plan without an attacker.
- No separate attacker provider or key flag: the attacker shares `--llm-provider` routing.

## Assumptions

- The not-run line uses the existing spec 086 `warnings` channel, as the A2A probes (spec 118) do
  for probes whose input is unset. Overturned if the owner wants a structured `not_run` list.
- Dropping PAIR vectors also applies to Python callers without `attacker_llm_client`; before,
  they were an error row. The Python docs and the example change with it.
