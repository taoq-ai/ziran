# Feature Specification: PoCs and reports show target text without live control characters

**Feature Branch**: `fix/report-text-safety`
**Created**: 2026-11-25
**Status**: Active
**Plan item**: C-ENGINE-TEXT-SAFETY (goal G-c)

## The promise in our own words

Two outputs pass text from the scanned agent to a person without neutralising control
characters.

1. The generated PoCs print the start of the agent's reply. The httpx Python PoC prints
   `reply.text[:200]`, the adapter Python PoC prints `response.content[:200]` and every tool
   name, and the cURL PoC prints `${RESPONSE:0:N}`. A hostile agent can put ESC, CSI, OSC or
   C1 codes in its reply and drive the operator's terminal: clear the screen, set the title,
   write the clipboard (CWE-150).
2. The Markdown report puts target-named tool ids and tag owners in table rows, list items
   and headings with raw control characters. A newline in a tool id ends the chain table row
   early, so the rest of the id renders as a new paragraph (CWE-116). The HTML report escapes
   HTML but leaves bidi and control characters live.

After the fix:

- Every reply excerpt and tool name a generated PoC prints is on one line with controls
  escaped. The Python PoCs backslash-escape every non-printable character (`\x1b`, `\u202e`,
  `\n`). The cURL PoC pipes the excerpt through `LC_ALL=C tr '\n' ' ' | LC_ALL=C cat -vt`, so
  control bytes show as `^[`, `^M` and `M-` text.
- Matching is unchanged: the PoCs still match indicators against the raw reply, and the exit
  codes (0 reproduced, 1 not, 2 nothing to check, 3 unreadable) and #562's quoting stay.
- The Markdown report renders target-named values (chain tools, critical path nodes,
  blast-radius ids, tag owners, warnings) through one helper, `ziran.domain.text.printable`,
  inside code spans, and escapes `|` in every chain table cell. A tool id with `\n` and U+202E
  keeps one table row and shows `\n` and `\u202e` as text.
- A value whose longest backtick run is 80 or more cannot be fenced (cmark-gfm opens no code
  span over 80 backticks), so it renders as escaped text instead: controls through
  `printable`, then every ASCII punctuation mark but `|` backslash-escaped. GFM links an
  email address (and `mailto:`, `xmpp:`) even through escapes or `&#64;`, so each run of `@`
  becomes its own code span (`` `@` ``), which splits the text the autolink scans.
- The chain description and remediation hold raw tool ids when typed chains are on, so they
  render as the same escaped text: no heading, link or emphasis can go live.
- The HTML report passes the same values through `printable` before `html.escape`, the graph
  node labels included.

## Acceptance scenarios

1. Given a reply holding `ESC[2J`, OSC 0 and OSC 52 sequences, C1 CSI, CR, NUL, DEL and
   U+202E, when the cURL and httpx PoCs print it, then stdout holds no raw control character
   and the PoC still exits 0 on the canary.
2. Given an adapter reply and tool name holding the same codes, when the adapter PoC prints
   them, then stdout holds no raw control character.
3. Given a tool id with a newline and U+202E, when the Markdown report renders, then the chain
   table keeps one row and shows the escaped id; the critical path and tag owner show escaped.
4. Given the same id, when the HTML report renders, then it shows the escaped id, HTML-escaped.
5. Given a typed chain whose tool id holds `\n# OWNED`, controls and a Markdown link, when the
   Markdown report renders, then the table keeps one row a chain, no heading starts a line and
   the description and remediation show the escaped text.
6. Given a tool id with a run of 80 or 300 backticks and a Markdown link, when the report
   renders, then the id is escaped text and no fence or link remains.
7. Given an address, `mailto:` and `xmpp:` in a typed-chain id and in an 80-backtick id, when
   the report renders, then cmark-gfm links none of them.
8. Given a reply holding an LF and a forged `[+]` line, when each PoC prints it, then the
   excerpt stays on one line.
9. The existing hostile-prompt tests (spec 099) stay green.

## Assumptions

- The cURL excerpt uses `cat -v` in the C locale: non-ASCII text (`é`) shows as `M-` bytes.
  macOS `cat -v` in a UTF-8 locale passes a lead byte through raw, so the C locale is the
  portable choice. Overturned if operators need readable non-ASCII excerpts: then the script
  needs a UTF-8 aware filter.
- A reply newline is shown as `\n` (Python) or a space (cURL), so the excerpt stays one line.
- `ziran/domain/text.py` holds `printable`, moved from the PoC generator, because the CLI
  reports and the PoC generator both need it and domain is the layer both may import.
- Out of this item's scope, as a follow-up: the PoC Markdown guide (`generate_markdown_guide`),
  the raw `phase_result.error` line in the Markdown report, and bidi characters in the HTML
  attack log `<pre>`.
- `printable` shows a real newline and a literal backslash-n the same way; accepted.
- Spec number 104 is derived from `origin/develop` (highest 103,
  `103-tag-unreached-warning`) and the remote branches.
