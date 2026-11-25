# Plan: the study-v2.1 detector changes

Order of the build, as section 5.12 of the design gives it. Each step ends with its
design-half measurement (ziran-paper `study/scripts/revision_build.py` and `revision_design.py`).

1. Drift: `develop` with no change, measured on the design half.
2. The B1 hunt: analysis only, no rule.
3. Change 1: `knowledge_graph/role_typing.py` (`tool_roles`, `keyword_roles`); `hybrid/jobs.py`
   docstring; `blast_radius.py` and `trifecta.py` call `keyword_roles` and keep their behaviour.
4. Change 9: `knowledge_graph/chain_analyzer.py` (`_pattern_matches`).
5. Changes 2, 4 and 6: `static_analysis/claude_code_audit.py`, `claude_code_baseline.py`,
   `knowledge_graph/tool_aliases.py`, `infrastructure/config/claude_code_plugin.py`.
6. Change 3: `hybrid/jobs.py`, `hybrid/prompts/plausibility/v1.md`.
7. Change 7: `detectors/pipeline.py`, `side_effect.py`, `authorization.py`, `provenance.py`
   (`call_name`, `call_args`), `domain/entities/detection.py`, `agent_scanner/attack_executor.py`,
   `attacks/tactics.py`, `attacks/pair.py`, the report builders, `docs/concepts/detection-pipeline.md`.
8. Change 8: `detectors/provenance.py` (`_kinds`).

Held byte-identical to study-v1: `domain/tool_classifier.py`, `detectors/refusal.py`,
`detectors/llm_judge.py`, `domain/entities/claude_code.py`. Not edited: `application/strategies/`,
`agent_scanner/scanner.py`.

Rollback: revert the merge commit; every change is code and one prompt file, with no migration.
