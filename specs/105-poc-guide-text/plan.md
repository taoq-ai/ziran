# Plan: the PoC guide, phase errors and the HTML reply block show target text inert

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13), stdlib only. No new dependencies.

## Constitution check

- Hexagonal: the Markdown helpers move into `ziran/domain/text.py` (stdlib only), so the
  application PoC generator and the CLI reports both import inward. Pass.
- Types: annotated, mypy strict clean. Pass.
- Tests: unit tests render hostile values through the guide, report.md and the HTML report.
  Pass.
- Simplicity: one new helper (`md_block`) and one line-keeping variant of `printable`; the
  spec 104 helpers are reused, not copied. Pass.

## Design

1. `ziran/domain/text.py`: `printable_lines` (printable per line, newlines kept); `md_text`
   and `md_code` moved from reports.py; `md_block` picks a backtick fence of
   `max(3, longest run + 1)` under 256, else a tilde fence on the same rule, else `md_text`.
2. `ziran/application/poc/generator.py`: prompt and snippet through `md_block` (written with
   `MdUtils.write` in place of `insert_code`); indicators and tool names through `md_code`;
   detector reasoning through `md_text`.
3. `ziran/interfaces/cli/reports.py`: imports `md_text`/`md_code` as `_md_text`/`_md_code`;
   the phase error line through `_md_text`.
4. `ziran/interfaces/cli/html_report.py`: prompt and reply `<pre>` through
   `html.escape(printable_lines(...))`.
