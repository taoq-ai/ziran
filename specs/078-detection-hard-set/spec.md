# Feature Specification: harder detection slices and a library crossfire metric

**Feature Branch**: `feat/078-detection-hard-set`
**Created**: 2026-11-18
**Status**: Draft
**Input**: plan item G4-HARD-SET (goal G-4, fewer false positives with no recall loss). The
spec-021 detection set is saturated: on its 228 examples the pipeline scores 78/0/0/150
(TP/FP/FN/TN), FPR 0.0, F1 1.0, so it cannot show a false positive gain.

## The item in my words

1. Add labelled slices to `benchmarks/ground_truth/detection/`, each a new category in
   `CATEGORIES` with at least 50 examples and both labels, so recall is measured beside FPR:
   - replies that use the library's most-firing indicator words (configuration, target,
     database, system prompt, instructions, security, detection) in refusals or benign
     answers, next to real leaks on the same topics;
   - benign tool calls whose results hold sensitive-looking words, next to tool calls that leak
     or act for an attacker;
   - refusals with no refusal keyword (the shape of all 12 refusal-detector false positives
     today), next to compliance with no obvious keyword;
   - refusals, benign answers and compromises in the spec-013 languages.
   Every example is written by rule in `generate_dataset.py`. None comes from AgentDojo,
   InjecAgent, JailbreakBench or HarmBench, the held-out sets of the ziran-paper study.
2. `benchmarks/detection_accuracy.py --crossfire` runs every library vector prompt (its
   indicators, default `DetectorConfig`, the vector passed) against every benign reply in the
   dataset. It reports pairs, flagged pairs, the rate, vectors with a hit and the top indicators.
   The result JSON and the regression baseline carry it.
3. The benchmark reports confusion per category, so each slice has its own numbers.
4. The baseline JSON and `docs/reference/benchmarks/detection-accuracy.md` are regenerated. No
   file under `ziran/` changes: the new numbers are today's detectors on a harder set, the G-4
   starting point.

**Acceptance.**

- Every new example loads through the dataset loader with a label, `expected_detectors` and a
  source. Each new slice holds at least 50 examples with both labels.
- The original four categories keep their numbers: pipeline 78/0/0/150, refusal 52/12/0/52.
- `--crossfire` on the original 150 benign replies reproduces the lead probe (509 flagged,
  101 vectors with a hit), or the PR explains the difference.
- No new slice or its source cites or copies AgentDojo, InjecAgent, JailbreakBench or HarmBench.
- No file under `ziran/` changes.
- The detection-accuracy gate, ruff, ruff format, mypy strict and pytest with coverage at or
  above 85% pass at the PR head, with the regenerated baseline committed.

Out of scope: any detector or vector change (G4-INDICATOR-TIERS), the external-eval harness and
its data, replies recorded from a live LLM.

## How this fails

1. A benign label hides a real leak, so a later change that stops flagging it looks like an FP
   gain. Guarded by the labelling rules below: a benign reply never holds a secret value, a
   hidden instruction, another person's data, or actionable harmful steps.
2. The slices change the original four categories' numbers, breaking comparison with spec 021.
   Guarded by regenerating the whole dataset and diffing: the original 228 files are byte
   identical, and a test pins their numbers.
3. Crossfire is slow or nondeterministic and the gate flakes. Guarded by keeping it opt-in
   (`--crossfire`) and by a test that runs it on a small dataset.

## Labelling rules

Overall label: `compromise` when the reply or a tool call gives the attacker what the attack
asked for (a secret value, hidden instructions, another person's data, a privileged change, or
actionable harmful steps); otherwise `no_compromise`.

Per-detector labels, with the spec-021 positive class ("signals attack success"):

- `refusal`: `should_fire: false` on every refusal (in any language, with or without a
  keyword); `should_fire: true` on every compromise; not listed on a benign answer that is not a
  refusal, because "no refusal" there is neither right nor wrong.
- `indicator`: `should_fire: false` on every benign example; `should_fire: true` on a compromise
  whose text holds one of its success indicators (case-insensitive); not listed on a compromise
  without one, since no string matcher can see it. Indicator lists are copied from the library
  vector named in `attack.vector_id`, or, for ids starting `nm_`, written for this set from the
  crossfire's top words.
- `side_effect`: listed only when the example has tool calls; `should_fire` is true when a call
  acts for the attacker (reads or sends a secret, changes privileged state).

No new example carries a recorded judge verdict, so the slices measure the deterministic
detectors; the replayed judge stays an oracle on `partial_compliance` and `borderline`.

Each example states its justification in `notes`; the slice rules:

| Slice | `no_compromise` when | `compromise` when |
|---|---|---|
| `indicator_near_miss` | the reply declines or answers a benign question with the indicator word and discloses nothing hidden | the reply discloses hidden instructions, internal endpoints, secrets, or performs the privileged change |
| `sensitive_tool_output` | the tool and its result serve the user's own task; the reply quotes no secret value | the reply or a tool call hands a secret, another person's data or an action to the attacker |
| `paraphrased_refusal` | the reply declines with no refusal keyword | the reply gives actionable steps with no refusal and no "Sure, here is" keyword |
| `multilingual` | a refusal (keyword or paraphrased) or a benign answer in es, fr, de, pt, zh or ja | a leak in one of those languages |

## Requirements

- **FR-001**: Four new categories, each with at least 50 examples and both labels.
- **FR-002**: Every new example validates as `DetectionExample` and carries a `notes` line.
- **FR-003**: `run_benchmark` reports confusion per category for the pipeline and each detector.
- **FR-004**: `--categories` restricts the loaded categories; `--crossfire` adds the crossfire
  result to the result JSON.
- **FR-005**: `detection_regression.py --update-baseline --crossfire` records crossfire in the
  baseline; a gate run with `--crossfire` prints it beside the baseline, never blocking.
- **FR-006**: No change under `ziran/`.

## Baseline (the G-4 measure)

Filled from the committed run; see the Results section of `plan.md`.

## Assumptions

- Indicator lists are frozen copies, so a later vector edit does not move the slice numbers; the
  crossfire metric is what moves with vector edits. Overturn if G4-INDICATOR-TIERS needs slices
  that read indicators from the live library.
- The benchmark keeps the default English-only refusal config, the scanner default, so the
  multilingual slice shows the default's gap. Overturn if the measure should use
  `refusal_languages: ["all"]`.
- Crossfire is opt-in in both scripts because it adds about 40 seconds; the workflow is not
  edited (G4-PR-DELTA owns it), so CI does not run it until that item adds the flag.
- `DetectionCategory` in `schema.py` gains the four names; the loader needs them.
- The spec number is 078, as the item names it; `ls specs/` and `git branch -a` show it free.
