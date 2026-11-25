# Tasks: scan results printed to the terminal show target text inert

Base: `origin/develop` at e2db5a3. Branch `fix/cli-terminal-text`. Test first.

- [x] T001 Test: a hostile value (OSC 52, OSC 8, CSI 2J, U+202E, `[link=...]`) through the
  scan, analyze-traces, audit, ci gate, pentest and watch-registry output on a forced terminal
  console (`tests/unit/test_cli_terminal_text.py`). Run red: 6 failed.
- [x] T002 `_term` helper in `main.py`; every target-derived print and cell in the CLI goes
  through it or through `escape(printable(...))`.
- [x] T003 Touched tests green; ruff, format and mypy clean.
