Verdict: PASS
Gate: arch
Item: G3-VECTOR-BATCH
PR: taoq-ai/ziran#508
Head: a84c4307d618f10c052d86400db3b27bd416c7a3
Confidence: high
Breaking: no (minor: 8 data vectors and 2 additive AtlasTechnique members; no field, signature or exit code changed)

## Findings
- [low] specs/076-vectors-2026h2/spec.md:86 blocks: no. The Assumptions line (also in the PR body) says choosing `privilege_escalation` keeps the BOLA/BFLA detector off the n8n vectors. That is wrong. `DetectorPipeline._is_authz_vector` (ziran/application/detectors/pipeline.py:374-380) also routes by the `bola`/`bfla` tags, and both n8n vectors carry `bfla`, so `AuthorizationDetector` runs on them anyway (300 of 300 crossfire pairs). The category is still sound: both attacks end in command execution, and `privilege_escalation` maps to SYSTEM_COMPROMISE. The PII regexes are not shown to be wrong, since they flag 0 benign replies under either category. Correct the rationale, or drop the `bfla` tag if keeping the detector off was the intent.
- [low] docs/reference/benchmarks/atlas-mapping.md:115 blocks: no. Merge order: #505 makes the same `661-vector` to `669-vector` edit on this line, so git merges the line without a conflict. Whichever PR merges second leaves 669 for a 677-vector library. Fix it by hand after the rebase. The generated files (benchmarks/README.md, coverage-comparison.md, baseline.json) do conflict, so regenerating them is forced. `regression_check.py` fails only on a decrease, though, so a stale or lower baseline would still pass CI.
- [low] blocks: no. No test or CI step checks the hand-quoted counts in atlas-mapping.md (library size, enum size, TA0000 total, TA0000/TA0001 table) against `atlas_coverage.py --json`. This gap already existed. A short test would turn the merge-order risk above into a red check.

## Probes
- Scope: the diff against origin/develop has 10 files, all inside the item's Files list plus a test. There is no layer change: data under application/, the enum under domain/, and no new import.
- Schema conformance: the new file uses only the fields the other 657 vectors use (id, name, category, target_phase, severity, description, tags, references, owasp_mapping, atlas_mapping, prompts with template, variables, success_indicators and failure_indicators). Categories are tool_manipulation, indirect_injection and privilege_escalation, and target_phase is `execution`, like 530 existing vectors. It has no `protocol_filter`, unlike the 101 `[mcp]` vectors. That is correct: the MCP-config vectors attack an agent host over chat, not an MCP-protocol target.
- ATLAS IDs against mitre-atlas/atlas-data: AML.T0105 "Escape to Host" appears in dist/ATLAS.yaml at v5.4.0 (created 2026-01-30, tactic AML.TA0012). AML.T0142 "Event Triggered Execution" appears in ATLAS-latest.yaml at v2026.10 (created 2026-10-28) and is absent at v5.4.0. ATLAS case study CS0074 files T0142 under AML.TA0006 Persistence. The names, releases and tactic maps in attack.py all match.
- atlas_coverage.py at head: exit 0, 669/669 mapped, techniques 74/88, agent-specific 14/14, AML.TA0000 927. `--json` per-technique counts T0040 468, T0047 457, T0044 2, T0041 0, T0042 384, T0043 175, T0018 19/17/17/13, T0005 1 match the hand-edited atlas-mapping.md table and lines 6 and 115.
- Generated docs are fresh: generate_all.py (exit 0) and regression_check.py (exit 0, "No changes from baseline") reproduce benchmarks/README.md, coverage-comparison.md and baseline.json byte for byte in a git-archive copy.
- Crossfire (own probe, 150 no_compromise replies from benchmarks/ground_truth/detection, offline DetectorPipeline): head has 8 vectors and 1350 pairs with 0 flags. With the n8n vectors recategorised as authorization_bypass: 300 pairs, 0 flags. With the bfla tag removed: 300 pairs, 0 flags, and the authorization detector ran 0 times.
- Tests: test_vectors_2026h2, test_atlas_enum, test_atlas_coverage_script (integration) and test_library_atlas_filter: 25 passed.
- Mutant, in a fresh copy: removing the T0142 entry from ATLAS_TECHNIQUE_TO_TACTIC makes test_new_atlas_techniques_are_registered and test_tactic_map_covers_every_enum_member fail, so it is killed. The diff changes no other guard or validation.
- #505 overlap (gh pr diff 505, head 006161d): #505 adds 8 vectors, so the merged library holds 677. It adds no AtlasTechnique member, so the enum stays at 88. None of its vectors maps an AML.TA0000 or TA0001 technique, so 927 and the TA0000/TA0001 table hold. Its attack.py hunks (model_validator, mcp_server_request) do not overlap this PR's enum hunks. Its generate_all.py change only adds a line for the `mcp_server_surface` tag. Keep the plan's order (#505 first). After the rebase, this PR reruns generate_all.py and `regression_check.py --update-baseline` from the merged tree, never picking a side of the conflict, and sets atlas-mapping.md:115 to 677.
- Not run: full pytest --cov, ruff and mypy (the quality gate's job).
- Confidence high: every count and ID was re-derived from the scripts and the upstream ATLAS data, not taken from the builder's summary.

## Residual risk
The rebase after #505 has to hand-edit atlas-mapping.md:115, and CI will not notice if that is missed. Whether the vectors actually work against real Langflow, n8n or Claude Code hosts was not tested; that is the goal gate's job.
