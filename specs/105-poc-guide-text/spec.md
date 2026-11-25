# Feature Specification: the PoC guide, phase errors and the HTML reply block show target text inert

**Feature Branch**: `fix/poc-guide-text`
**Created**: 2026-11-25
**Status**: Active
**Plan item**: C-POC-GUIDE-TEXT (goal G-c)

## The promise in our own words

Spec 104 made the report's tool ids and chain text inert. Three places still pass target text
to a reader as it came:

1. The PoC Markdown guide (`PoCGenerator.generate_markdown_guide`) puts the agent's reply
   snippet and the prompt in a fixed three-backtick fence, and tool names and matched
   indicators in one-backtick spans. A reply holding a fence closes the block, so the rest
   renders as a live heading and links, and ESC, BEL and U+202E reach the file raw. The
   detector reasoning goes into a blockquote unescaped.
2. `report.md` prints `phase_result.error` raw: a newline starts a new block and a Markdown
   link goes live.
3. The HTML report's attack log shows the prompt and the reply in `<pre>` with HTML escaped
   but bidi and control characters live.

After the fix:

- The prompt and reply snippet render as one fenced block whose fence outruns every backtick
  run in the text. cmark-gfm opens no fence longer than 255 backticks, so a longer run takes a
  tilde fence; when the text also holds 255 or more tildes it falls back to escaped one-line
  text (`md_text`). Lines stay lines; each line's controls are backslash-escaped.
- Tool names and indicators render through `md_code` (spec 104), the detector reasoning and the
  phase error through `md_text`.
- The HTML prompt and reply blocks escape controls and bidi per line, then HTML-escape, so
  line breaks stay.
- `md_text` and `md_code` move from `ziran/interfaces/cli/reports.py` to `ziran/domain/text.py`
  beside `printable`, so the application layer can use them; the report imports them under its
  old names.

## Acceptance scenarios

1. Given a reply snippet holding a 300-backtick run, a fence and ESC/BEL/U+202E, when the PoC
   Markdown guide is generated, then cmark-gfm renders it as text with no heading, link or raw
   control.
2. Given a phase error holding a newline and a Markdown link, when report.md renders, then it
   stays one line with no live link.
3. Given a reply with a newline, U+202E, ESC and BEL, when the HTML report renders, then the
   `<pre>` block keeps the line break and shows the controls escaped.

## Assumptions

- The prompt block is ours (from the vector library), but a vector prompt can hold a fence, so
  it takes the same block helper. Overturned if a reviewer wants prompts verbatim.
- The fallback to one-line text only triggers when the text holds both 255 or more backticks
  and 255 or more tildes; the guide cuts snippets at 500 characters by default, so it needs a
  raised cap. A unit test drives `md_block` directly for it.
- Vector names, ids and the campaign id are not target text, so they stay as they are.
