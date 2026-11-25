# Plan: scan results printed to the terminal show target text inert

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Rich (already a dependency) and stdlib only. No
new dependencies.

## Constitution check

- Hexagonal: the CLI (interfaces) imports `printable` from the domain. Pass.
- Types: annotated, mypy strict clean. Pass.
- Tests: one parametrised unit test renders a hostile value through six output functions on a
  forced terminal console. Pass.
- Simplicity: one private helper `_term` in `main.py`; the two other CLI modules call
  `escape(printable(...))` inline, since importing from `main` would be circular. Pass.

## Design

1. `ziran/interfaces/cli/main.py`: `_term(value) = escape(printable(str(value)))` beside the
   module console; each target-derived Rich string or cell goes through it. A cut (`[:50]`,
   `[:60]`) happens before the escape, so an escape sequence is never split.
2. `ziran/interfaces/cli/analyze_traces.py`, `watch_registry.py`: the same call inline.
