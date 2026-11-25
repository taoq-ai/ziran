# Tasks: scan results printed to the terminal show target text inert

Base: `origin/develop` at e2db5a3. Branch `fix/cli-terminal-text`. Test first.

- [x] T001 Test: a hostile value (OSC 52, OSC 8, CSI 2J, U+202E, `[link=...]`) through the
  scan, analyze-traces, audit, ci gate, pentest and watch-registry output on a forced terminal
  console (`tests/unit/test_cli_terminal_text.py`). Run red: 6 failed.
- [x] T002 `_term` helper in `main.py`; every target-derived print and cell in the CLI goes
  through it or through `escape(printable(...))`.
- [x] T003 Touched tests green; ruff, format and mypy clean.
- [x] T004 Fix round (quality, security and arch at 250b283): `term()` moves to
  `ziran/interfaces/cli/_text.py`; the log handler runs with `markup=False`; `validate`
  detail, the analyze-traces error, the campaign id and the pentest progress view escaped.
  The test covers every wrapped site: discover, audit narrowed panel, ci warnings and gate
  violations, policy verdict, phase findings, the pentest REPL, validate, progress and the
  log handler.
