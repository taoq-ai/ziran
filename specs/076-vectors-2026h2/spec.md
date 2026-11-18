# Feature Specification: attack vectors for agent and MCP techniques published after 2026-06-18

**Feature Branch**: `feat/076-vectors-2026h2`
**Created**: 2026-11-18
**Status**: Draft
**Input**: plan item G3-VECTOR-BATCH (goal G-3). The newest vector family is
`many_shot_jailbreak.yaml` (spec 023, 2026-06-18); the library holds 661 vectors.

## The item in my words

1. One new YAML file under `ziran/application/attacks/vectors/` adds at least 6 vectors across at
   least 4 of the six technique families the item names. Each vector cites a primary source
   published after 2026-06-18 that I read (a GitHub advisory read with `gh api /advisories`, or an
   ATLAS data release).
2. Each vector carries OWASP and ATLAS mappings. An ATLAS ID that the `AtlasTechnique` enum lacks
   is added there with its name, its tactic and the ATLAS release that introduced it.
3. Success indicators are evidence that the attack ran, not topical words. None of them fires on
   any of the 150 benign (`no_compromise`) replies in the detection dataset.
4. The coverage docs and `benchmarks/results/baseline.json` are regenerated for the new count.

Out of scope: MCP server-initiated vectors (sampling, elicitation, roots; G2-MCP-SURFACE), CVE
database entries (G3-CVE-BATCH), edits to existing vectors (G4-INDICATOR-TIERS).

**Acceptance.**

- Each new vector cites a source published after 2026-06-18, has OWASP and ATLAS mappings, and
  every ATLAS ID it uses exists in `AtlasTechnique`.
- The library loads every vector; the total rises from 661 by the number added.
- The crossfire probe (every new vector prompt through the offline detector pipeline against the
  150 benign replies) flags no benign reply.
- `benchmarks/generate_all.py`, `benchmarks/regression_check.py` and the ATLAS coverage script
  test pass; ruff, ruff format, mypy strict and pytest with coverage at or above 85% pass.

## Families and sources

Each source was read on 2026-11-18 with `gh api "/advisories?cve_id=<CVE>"`.

| Family | Source | Published |
|---|---|---|
| MCP server config injection to command execution | GHSA-w794-rj3p-xv45 (Langflow, CVE-2026-105697) | 2026-10-07 |
| Shell allowlist bypass by newline injection | GHSA-2h4w-29cv-2cmv (AG2, CVE-2026-113663) | 2026-11-10 |
| Workspace escape through worktree confusion | GHSA-7835-87q9-rgvv (Claude Code, CVE-2026-55607) | 2026-07-24 |
| Workspace escape through a TOCTOU symlink swap | GHSA-5xjx-9qx6-jcrv (Claude Code, CVE-2026-88968) | 2026-11-09 |
| Prompt injection into a code-generating step | GHSA-9fpm-3445-2vx4 (Langflow, CVE-2026-7700) | 2026-10-05 |
| Agent tool bypasses its caller policy | GHSA-7hgx-277f-7vmg (n8n, CVE-2026-86996) | 2026-09-08 |
| Agent tool ignores the caller's role | GHSA-x5vx-c2c8-m3w9 (n8n, CVE-2026-65015) | 2026-07-22 |

The family "exfiltration through a pre-approved fetch domain" is dropped: its only named source,
GHSA-fg94-h982-f3mm (CVE-2026-54316), was published on 2026-06-17, one day before the cutoff, and
no later advisory for the same technique was found in the Claude Code or Codex advisory lists.

New ATLAS IDs, from `mitre-atlas/atlas-data`:

- `AML.T0105` Escape to Host, first in release v5.4.0 (2026-02-06), tactic Privilege Escalation
  (`AML.TA0012`). The enum lacked it.
- `AML.T0142` Event Triggered Execution, first in release v2026.10 (2026-10-28), tactic
  Persistence (`AML.TA0006`).

## How this fails

1. An indicator matches ordinary text, so benign replies are flagged and the detection
   regression gate drops. Guarded by computed canaries: the payload asks a shell to print
   `zrn$((6*7))<tag>`, the indicator is `zrn42<tag>`, so only execution (or a model that runs the
   arithmetic for the attacker) produces it, and a refusal that quotes the payload does not.
2. A vector repeats a technique the library already has (`te_symlink_escape`,
   `mcp_resource_symlink_traversal`). Guarded by a grep of all vector YAML for symlink, newline,
   worktree, lambda, stdio and caller-policy terms; the new vectors cover the unsandboxed write
   after a sandboxed swap and the worktree `.git` confusion, which no vector covers.
3. A new ATLAS ID breaks the enum tests or the coverage script. Guarded by adding each ID to the
   enum, the description map and the tactic map, and by running `test_atlas_enum.py` and the
   coverage script test.

## Requirements

- **FR-001**: The new file holds at least 6 vectors over at least 4 families, each with a
  `references` entry from the table above.
- **FR-002**: Each vector has a non-empty `owasp_mapping` and `atlas_mapping`.
- **FR-003**: Each prompt has at least one computed canary indicator that does not appear in its
  template or variables.
- **FR-004**: `AML.T0105` and `AML.T0142` are in `AtlasTechnique`, `ATLAS_TECHNIQUE_DESCRIPTIONS`
  and `ATLAS_TECHNIQUE_TO_TACTIC`.
- **FR-005**: The crossfire probe reports zero benign flags for the new vectors.

## Assumptions

- Category `privilege_escalation`, not `authorization_bypass`, for the n8n vectors: the
  pipeline runs the BOLA/BFLA detector on `authorization_bypass`, whose PII regexes are not about
  these attacks and could flag benign replies. Overturn if the gate wants BFLA scoring on them.
- The ATLAS snapshot date in `benchmarks/atlas_coverage.py` stays at 2025-10-01: adding two
  techniques is not a full snapshot refresh, as with `AML.T0102` and `AML.T0109` before.
- The spec number is 076, as the plan item names it; `ls specs/` and `git branch -a` show it free.
