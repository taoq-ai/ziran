# Tasks: PoCs and reports show target text without live control characters

Base: `origin/develop` at b90bfc0. Branch `fix/report-text-safety`. Test first.

- [x] T001 Tests: hostile raw reply through the cURL and httpx PoCs on both protocols
  (`test_poc_target_protocol.py`), hostile adapter reply and tool name
  (`test_poc_generator.py`), a control-character tool id through the Markdown chain table,
  critical path and tag owner, and through the HTML report (`test_blast_radius_report.py`);
  the old newline-to-space `_md_code` expectations updated. Run red: 7 failed.
- [x] T002 `ziran/domain/text.py` `printable`; PoC `_shown` helper and cURL `cat -vt` filter.
- [x] T003 Markdown and HTML renderers use `printable`; chain table cells escape `|`.
- [x] T004 Touched tests green (604 passed, 4 skipped); ruff, format and mypy clean.
- [x] T005 Mutants in an archive copy under `timeout -s KILL 120`, each killed by a new test.
- [x] T006 Fix round (security and quality gates at 5f28df7): merged develop a4c9c6e, renamed
  the spec to 104; tests first for typed-chain text, 80 and 300 backtick ids, an LF-forged PoC
  line, warnings, chain-target cells, tooltips and graph labels; `_md_text` escaped-text
  fallback in `_md_code`, description and remediation through `_md_text`, graph labels
  through `printable`. Checked under cmark-gfm: one chain row, no live link or heading.
