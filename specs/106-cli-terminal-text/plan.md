# Plan: scan results printed to the terminal show target text inert

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13). Rich (already a dependency) and stdlib only. No
new dependencies.

## Constitution check

- Hexagonal: the CLI (interfaces) imports `printable` from the domain. Pass.
- Types: annotated, mypy strict clean. Pass.
- Tests: one parametrised unit test renders a hostile value through every output function
  that prints target text, on a forced terminal console, plus one test on the log handler.
  Pass.
- Simplicity: one helper `term()` in a leaf module `ziran/interfaces/cli/_text.py`, imported
  by main.py, analyze_traces.py and watch_registry.py. A leaf module imports nothing from the
  CLI, so no cycle. `progress.py` sits in the application layer and calls
  `escape(printable(...))` inline, since it must not import from interfaces. Pass.

## Design

1. `ziran/interfaces/cli/_text.py`: `term(value) = escape(printable(str(value)))`. Each
   target-derived Rich string or cell in main.py, analyze_traces.py and watch_registry.py goes
   through it. A cut (`[:50]`, `[:60]`) happens before the escape, so an escape sequence is
   never split.
2. `ziran/application/pentesting/progress.py`: the live pentest view escapes the agent event
   message and the attack name inline.
3. `ziran/infrastructure/logging/logger.py`: the text-format RichHandler runs with
   `markup=False`. No ziran log call uses markup, and log values carry target text (the A2A
   card name and version, a target's JSON-RPC error).
