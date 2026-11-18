Verdict: PASS
Gate: arch
Item: G4-INDICATOR-TIERS
PR: taoq-ai/ziran#514
Head: fea1eaa7aa8832eb5f31d7fbdac986e7638abf03
Confidence: high
Breaking: no (patch: a heuristic detector scores one ambiguous case lower; no API element, config key, output shape or exit code changes)

## Findings
- [low] blocks: no. Maintenance: the 19-word `_CORROBORATED_INDICATORS` list and the "every library prompt keeps a strong indicator or two corroborated words" property live only in a scratch probe. A future vector whose only indicator is a corroborated word (for example `endpoint`) would silently lose its offline confident hit, and the detection gate would not see it unless the dataset covers that vector. A committed library-wide unit test (930 prompts, assert none newly loses confident evidence) would make it a fitness function. spec 027's `_GENERIC_INDICATORS` has the same gap today.
- [low] ziran/application/detectors/indicator.py:229 blocks: no. The ambiguous-result reasoning still says "Only generic indicator(s) matched" when the match is a single corroborated word, so an operator reading a finding's reasoning sees the wrong tier name.
- [low] blocks: no. PR body: the user-visible effect is not stated as a release note. Scans without an LLM judge now report fewer findings where one corroborated word was the only evidence, so `ziran ci` gates can pass where they failed. The `fix(detectors)` commit subject reaches the release-please CHANGELOG (spec 027 shipped the same way as "eliminate indicator-matching false positives"), but one plain line about fewer findings would help existing users.

## Probes
- Conformance: spec 027 FR-004 tiers weak single words in indicator.py through `_is_strong_indicator`, and its edge case names "requiring corroboration or an evidence-bearing phrase". This change adds a list beside `_GENERIC_INDICATORS` plus one condition in `detect`. It follows that design, edits no vector, and keeps the FR-005 guards (negation, echo, capability) ahead of tiering.
- Placement: `DetectorThresholds` (thresholds.py, loaded from `.ziran/detectors.yaml` by infrastructure/config/detectors.py) holds only numeric pipeline thresholds, never word lists, and the spec-027 generic list is hardcoded in indicator.py. Keeping the new list there is consistent. Making it operator-configurable would add config surface and let local scans drift from the gated baseline (YAGNI). No new config key.
- Dependencies: indicator.py imports are unchanged (re, typing, domain DetectorResult). `git grep _is_strong_indicator|_CORROBORATED` shows indicator.py and the test file as the only users, so there is no new coupling or cycle. Hexagonal layering is intact.
- Touched tests: `timeout 120 pytest tests/unit/test_detectors.py` in a git archive copy of fea1eaa gave 57 passed.
- Mutants, each in a fresh archive copy, all killed. m1 (`>= _CORROBORATION_MIN` changed to `>= 1`) fails test_refusal_naming_the_configuration_is_not_a_hit. m2 (corroboration clause dropped) fails test_config_disclosure_with_credentials_still_hits. m3 (corroborated exclusion dropped from `_is_strong_indicator`) fails test_is_strong_indicator_classification and test_refusal_naming_the_configuration_is_not_a_hit.
- Detection gate at head against the new baseline: OK, pipeline F1 0.7348, delta 0.
- Detection gate at head against the old origin/develop baseline: OK, pipeline F1 0.6667 to 0.7348, so no pipeline recall drop or FPR rise under #509's zero-tolerance rule. The new baseline records pipeline FPR 0.2045 and recall 0.8582 (115/64/19/249). From now on that FPR is the ceiling later PRs must not exceed, which is the gate working as designed.
- Baseline diff: indicator_flagged goes from 1170 to 539 (at or under the target of 702), and vectors with an indicator hit go from 171 to 151. Crossfire flagged pairs go from 15060 to 14446. The JSON keeps the same shape.
- Vector library probe (all 930 prompts at the head): 0 prompts lose confident evidence through spec 079. 238 prompts have no confident indicator, and these predate the change: 236 have an empty indicator list and 2 were already all-generic.
- Hot path: one set comprehension per detect call over the matched indicators, which costs nothing measurable.
- Breaking: no public signature, config key, report or SARIF field, or exit-code meaning changes. Finding counts fall for one ambiguous case that spec 027 already routes to the judge. The `ziran ci` suppression baseline (spec 046) only sees findings that disappear, which resolve without error. This is a patch, matching the spec 027 precedent.
- Confidence high: the gate ran both ways, all three mutants were killed, and the library probe is clean. A real-world leak that matches exactly one corroborated word with no judge configured would lower it.

## Residual risk
Offline scans, with no judge, now miss a leak whose only matched evidence is one of the 19 corroborated words. The library probe and the dataset show none today, but nothing committed keeps it that way as vectors change.
