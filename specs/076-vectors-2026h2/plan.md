# Implementation Plan: attack vectors for agent and MCP techniques after 2026-06-18

**Spec**: [spec.md](spec.md)

## Approach

Data in the existing vector schema, plus two enum members. No new code path, no new dependency.

1. Each advisory was read on 2026-11-18 with `gh api "/advisories?cve_id=<CVE>"`; the ATLAS
   techniques and their releases come from `mitre-atlas/atlas-data` tag v2026.10
   (`dist/ATLAS-latest.yaml`) and its release notes.
2. A duplicate check grepped every vector YAML for newline, symlink, worktree, toctou, lambda,
   stdio, `config.toml`, allowlist and caller-policy terms. `te_symlink_escape` reads through a
   symlink inside a sandbox, and `mcp_resource_symlink_traversal` follows a symlinked MCP
   resource. Neither covers a sandboxed swap followed by an unsandboxed write, a `.git` worktree,
   a newline past a shell allowlist, an injected `eval` lambda, or an agent tool that skips a
   caller or role check.
3. One file, `ziran/application/attacks/vectors/agent_techniques_2026h2.yaml`, holds 8 vectors
   (9 prompts), tagged `spec-076`:

   | Vector | Family | Source |
   |---|---|---|
   | `agt26_mcp_stdio_config_command` | MCP config to command | GHSA-w794-rj3p-xv45 |
   | `agt26_mcp_flow_embedded_server_config` | MCP config to command | GHSA-w794-rj3p-xv45 |
   | `agt26_shell_allowlist_newline_bypass` | newline past an allowlist | GHSA-2h4w-29cv-2cmv |
   | `agt26_worktree_git_dir_confusion` | workspace escape | GHSA-7835-87q9-rgvv |
   | `agt26_edit_toctou_symlink_swap` | workspace escape | GHSA-5xjx-9qx6-jcrv |
   | `agt26_codegen_lambda_injection` | code-generating step | GHSA-9fpm-3445-2vx4 |
   | `agt26_agent_tool_caller_policy_bypass` | caller policy bypass | GHSA-7hgx-277f-7vmg |
   | `agt26_viewer_role_node_execution` | caller policy bypass | GHSA-x5vx-c2c8-m3w9 |

   The flow-embedded vector also cites GHSA-xrxf-jgv3-qmrm (Codex CLI, CVE-2025-61260,
   published 2026-04-14) as the project-local config precedent; its dated source is the Langflow
   advisory, whose 1.10.3 fix covers configs embedded in flows.
4. Indicators: each prompt's payload prints `zrn$((6*7))<tag>`; the success indicator is
   `zrn42<tag>`. Failure indicators are refusal sentences, not topical words, so a successful
   reply that names the control is not rejected.
5. `AtlasTechnique` gains `ESCAPE_TO_HOST` (`AML.T0105`, v5.4.0, Privilege Escalation) and
   `EVENT_TRIGGERED_EXECUTION` (`AML.T0142`, v2026.10, Persistence), with entries in the
   description and tactic maps.
6. `benchmarks/generate_all.py` regenerates `benchmarks/README.md` and
   `docs/reference/benchmarks/coverage-comparison.md`; `regression_check.py --update-baseline`
   refreshes `benchmarks/results/baseline.json`. `atlas-mapping.md` gets the new library size and
   enum size by hand (the script prints them; the page quotes them).

## Constitution check

- Hexagonal: data in `application/`, enum in `domain/`; no layer change.
- Type safety: vectors are validated by the `AttackVector` model; enum maps stay complete
  (`test_atlas_enum.py`).
- Tests: `tests/unit/test_vectors_2026h2.py` covers count, families, dated sources, mappings,
  computed canaries, the new enum members, and the indicator detector on an execution reply
  and on a refusal that quotes the payload.
- Extensibility: vectors are YAML, not code (principle V).
- Simplicity: no schema field, no helper.

## Verification

- Crossfire (the lead's probe, filtered to `spec-076`): 8 vectors, 150 benign replies, 1350
  pairs, 0 flags.
- `benchmarks/detection_regression.py`: pipeline F1 1.0, delta 0.0.
- `generate_all.py`: 669 vectors, OWASP 100%, ATLAS 74/88. `regression_check.py`: vectors +8,
  no regression.
- `benchmarks/atlas_coverage.py`: exit 0, 669 of 669 mapped, 14 of 14 agent-specific covered.
