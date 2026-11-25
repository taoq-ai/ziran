# Tasks: the PoC guide, phase errors and the HTML reply block show target text inert

Base: `origin/develop` at c1bf398. Branch `fix/poc-guide-text`. Test first.

- [x] T001 Tests: hostile reply snippets (a fence, a 300-backtick run, ESC/BEL/U+202E, an
  address), tool names, indicators and reasoning through the guide (`test_poc_generator.py`);
  a hostile phase error through report.md and a hostile reply through the HTML report
  (`test_blast_radius_report.py`). Run red: 6 failed.
- [x] T002 `ziran/domain/text.py`: `printable_lines`, `md_block`; `md_text` and `md_code`
  moved from reports.py.
- [x] T003 Guide, phase error and HTML `<pre>` blocks use them.
- [x] T004 Touched tests green; ruff, format and mypy clean.
- [x] T005 Hostile guides and report.md rendered with cmark-gfm on the base and the branch:
  no heading, link, address link or raw control on the branch.
