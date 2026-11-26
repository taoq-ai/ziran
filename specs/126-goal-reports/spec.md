# Feature Specification: goal state in every report and in ziran ci

**Feature Branch**: `feat/126-goal-reports`
**Created**: 2026-11-26
**Status**: Draft
**Input**: plan item F-GOAL-REPORTS (goal G-f, tier standard). Follows the arch gate on #598:
specs 116 and 124 record `goal_met` and `goal_evidence` only in the JSON result rows.

## The item in my words

A vector with a side-effect goal (spec 116) or a negotiation goal (spec 124) gets a verdict
beside its text verdict: met, not met, or unmeasured (`goal_met: null`). Today only the JSON
rows carry it. The Markdown, HTML and console reports and `ziran ci` read `successful` alone, so
an agent that sold under its floor reads as a pass everywhere a person looks.

Every report format must list each goal vector with its state and the turn of the evidence, and
an unmeasured goal must never read as not met (safe). `ziran ci` must be able to fail the build
on a met goal, through the gate config it already reads and the exit code it already uses.

**Acceptance, in my words.**

1. A scan where a `limit_breach` goal is met (the seller calls `submit_offer` at 650 on turn 3,
   floor 800): the Markdown, HTML and console reports each show that vector as `met`, with
   `turn 3: submit_offer commitment at $.price`.
2. `ziran ci` with a gate config that sets `fail_on_goal_met: true` on that result exits 1, and
   its output names the vector.

## Requirements

- **FR-001** `AttackResult` gains `goal_type` (the goal's `type`, `null` with no goal), set where
  the goal is judged. It tells a goal vector with no reply (`goal_met: null`) from a vector with
  no goal.
- **FR-002** One domain function, `goal_rows`, gives each goal vector's id, state (`met`,
  `not met`, `unmeasured`) and evidence text from serialised rows. A row from a file older than
  FR-001 counts when its `goal_met` is not null.
- **FR-003** Markdown: a `Goals Met` summary row (`1 of 3 (1 unmeasured)`) and a Side-Effect
  Goals table. HTML: the same as a section. Console: the summary row and a table. Target text
  (vector ids, tool names) is escaped in each format.
- **FR-004** `QualityGateConfig.fail_on_goal_met` (default `false`): when true, each met goal is
  a `goal_met` violation (critical) naming the vector and its evidence, and the gate fails with
  the existing exit code 1.
- **FR-005** `ziran ci` prints each met or unmeasured goal on every run, gate or not.
- **FR-006** With repeat trials, a goal met on any trial is met on the combined row, with that
  trial's evidence, even when another trial is the text success the row shows.
- **FR-007** `ziran ci` on a SARIF with `fail_on_goal_met: true` exits 1 and says why: a SARIF
  holds no goal verdicts, so the rule cannot be applied.
- **FR-008** No change to detectors, the hybrid judge, role typing, tool aliases or
  `chain_patterns.yaml`; `scanner.py` gains no line.

## Assumptions

- The goal gate is opt-in (`fail_on_goal_met: false` by default). Why: a default of true would
  fail result files that pass today wherever a custom vector carries a goal, a breaking change.
  The built-in library has no goal vector, so the default changes nothing for it. Overturned if
  the owner wants goals to gate by default in the next major.
- A met goal is a `critical` violation. Why: a goal is written by the owner for a limit that
  must hold; it has no severity of its own. Overturned if goals gain a severity field.
- An unmeasured goal does not fail the gate; `ziran ci` names it on every run, as it already
  warns on unmeasured vectors. Overturned if unmeasured goals should fail behind their own rule.
- The gate rule lives in the gate YAML only, with no new CLI flag, since the brief asked to reuse
  the gate options `ziran ci` already has.
- SARIF output and the GitHub step summary are unchanged: the item names Markdown, HTML,
  console and `ziran ci`. The violation shows in the step summary through the gate's violations.

## Out of scope

Goal results in SARIF; a severity per goal; a goal gate for unmeasured goals; the web UI.
