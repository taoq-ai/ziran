# Tasks: Sigma detection rules from proven chains

**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

- [x] T001 Grep `ziran/` for detection content (none); trace `PolicyRenderer`, `ExportService`, the `export-policy` CLI, `chain_fingerprint`, recorded `evidence.tool_calls` and `probe_markers`
- [x] T002 Write `tests/unit/test_sigma_renderer.py` and the CLI tests in `tests/integration/test_export_policy_cli.py`; run them red (unit: collection error, module missing; CLI: 2 failed)
- [x] T003 Add `GuardrailPolicyFormat.SIGMA`
- [x] T004 Add `ziran/infrastructure/policy_renderers/sigma_renderer.py` (`SigmaRenderer`, `sigma_schema_errors`, `sigma_matches`, the self-check)
- [x] T005 Wire `--format sigma` and `--exclude-probes` into `ziran export-policy`
- [x] T006 Run the new and touched tests green
- [x] T007 Validate example output against the Sigma specification's JSON schemas and pySigma in a scratch environment (not a dependency)
- [x] T008 Document in `docs/guides/detection-rules.md` and the mkdocs nav
- [x] T009 Run ruff check, ruff format --check and mypy strict
