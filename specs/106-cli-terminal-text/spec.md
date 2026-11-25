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
- Exception text printed after a failed load (`Error loading agent: {e}`) is out of scope: it
  is not a scan result. It is a follow-up candidate, since an HTTP error can carry target text.
- Vector names, ids, phase names and OWASP categories come from ziran's own library and stay
  as they are.
- `discover` has no test of its own: it needs a live adapter. Its cells take the same helper.
