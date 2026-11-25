# Feature Specification: scan results printed to the terminal show target text inert

**Feature Branch**: `fix/cli-terminal-text`
**Created**: 2026-11-25
**Status**: Active
**Plan item**: C-CLI-TERMINAL-TEXT (goal G-c)

## The promise in our own words

Specs 104 and 105 made the written reports inert. The terminal output still is not: the CLI
puts target values (tool names, chain text, reply excerpts, finding text built from them) into
Rich strings and table cells as they came. Rich reads `[link=...]` and `[bold]` in them as
markup, and Rich does not strip ESC, so an OSC 52 clipboard write, an OSC 8 hyperlink or a CSI
screen clear in a tool name reaches the operator's terminal. One hostile tool name produced
6 OSC 8 hyperlinks, 2 OSC 52 writes and a screen clear (CWE-150).

After the fix every target-controlled value the CLI prints goes through
`rich.markup.escape(printable(...))`, with `printable` from `ziran/domain/text.py`: controls
and bidi characters show backslash-escaped and markup shows as text. A line printed with
`markup=False` takes `printable` alone.

Sites covered:

- `scan` results (`_display_results`): target agent name, finding names and severities,
  critical path tools, dangerous chain type, tools, risk and description.
- `discover`: capability id, name and description.
- `validate`: the URL check detail, which carries the target's HTTP reason phrase.
- Log lines on stderr: the text-format handler no longer parses Rich markup.
- `pentest` live progress: the agent event message and the attack name.
- `audit` (`_display_audit_report` and the baseline-narrowed panel): finding message,
  location and recommendation.
- `ci` (`_display_gate_result`, the result warnings) and `--policy` (`_display_policy_verdict`):
  violation messages, unsuppressed finding labels and summaries.
- `pentest`: agent reply summaries, step tool names and results, finding titles.
- `analyze-traces`: campaign id, source and chain cells.
- `watch-registry`: server name, tool name and message.

## Acceptance scenarios

1. Given a scanned agent with a tool named with OSC 52, OSC 8, CSI 2J, U+202E and Rich
   `[link=...]` markup, when `ziran scan` prints its results, then the terminal output holds no
   raw control sequence and no live markup.
2. The same hostile value through the audit, ci gate, pentest, analyze-traces and
   watch-registry output gives the same result.

## Assumptions

- Operator inputs (paths, CLI options, the target config file, the goal) are not target text
  and stay as they are. Overturned if the gate treats the target YAML as hostile.
- Exception text printed after a failed load (`Error loading agent: {e}`) is out of scope:
  `load_remote_adapter` makes no network call, so `e` is operator config text.
- A stdlib log message with raw target text would still pass ESC to stderr: `markup=False`
  stops markup only. No ziran log call puts raw target text in the message; structlog key
  values are repr'd.
- Vector names, ids, phase names and OWASP categories come from ziran's own library and stay
  as they are.
