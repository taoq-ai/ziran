# Plan: PoCs and reports show target text without live control characters

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13), stdlib only. No new dependencies.

## Constitution check

- Hexagonal: `printable` lives in `ziran/domain/text.py` (stdlib only); the application PoC
  generator and the CLI reports import it inward. Pass.
- Types: annotated, mypy strict clean. Pass.
- Tests: unit tests drive the generated scripts and both report formats. Pass.
- Simplicity: one helper reused by three renderers; the generated scripts carry their own
  copy because they run without ziran installed. Pass.

## Design

1. `ziran/domain/text.py`: `printable(value)` escapes every non-printable character with
   `unicode_escape` (the PoC generator's existing `_printable`, moved).
2. `ziran/application/poc/generator.py`: a `_shown` helper is prepended to both Python PoC
   bodies; the reply excerpt and tool names go through it. The cURL excerpt pipes through
   `LC_ALL=C tr '\n' ' ' | LC_ALL=C cat -vt`.
3. `ziran/interfaces/cli/reports.py`: `_md_code` uses `printable` instead of joining lines;
   critical paths, the chain table and remediation tools use `_md_code`; chain table cells
   escape `|`; warnings go through `printable`.
4. `ziran/interfaces/cli/html_report.py`: `_esc = html.escape(printable(str(v)))` for node
   tooltips, blast radius, chain targets, warnings and critical paths.

## Files

- `ziran/domain/text.py` (new), `ziran/application/poc/generator.py`,
  `ziran/interfaces/cli/reports.py`, `ziran/interfaces/cli/html_report.py`.
- Tests: `tests/unit/test_poc_target_protocol.py`, `tests/unit/test_poc_generator.py`,
  `tests/unit/application/test_blast_radius_report.py`.
