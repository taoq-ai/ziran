"""Target text shown to a person: one line, no live control character."""

from __future__ import annotations

import re

#: cmark-gfm opens no code span whose fence is longer than this.
_MAX_SPAN_FENCE = 80
#: cmark-gfm opens no fenced code block whose fence is longer than this.
_MAX_BLOCK_FENCE = 255


def printable(value: str) -> str:
    """``value`` with every non-printable character (C0, C1, ESC, bidi) backslash-escaped.

    A newline becomes ``\\n``, so the value stays on one line in a table row or a terminal.
    """
    return "".join(
        c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in value
    )


def printable_lines(value: str) -> str:
    """``value`` as :func:`printable` escapes it, keeping each ``\\n`` as a line break."""
    return "\n".join(map(printable, value.split("\n")))


def md_text(text: str) -> str:
    """*text* as inert Markdown text on one line: controls and ASCII punctuation escaped.

    ``|`` is left to the table cell escape, so a cell does not show a stray backslash. GFM
    links an address even through an escape, so ``@`` becomes a code span that splits it.
    """
    return re.sub(
        r"@+|[!-/:-?\[-`{}~]",
        lambda m: f"`{m[0]}`" if m[0][0] == "@" else "\\" + m[0],
        printable(text),
    )


def _longest(char: str, text: str) -> int:
    return max(map(len, re.findall(re.escape(char) + "+", text)), default=0)


def md_code(text: str) -> str:
    """*text* as one Markdown code span: controls escaped, the fence outruns its backticks.

    A backtick run cmark-gfm could not fence falls back to escaped text.
    """
    text = printable(text) or " "  # an empty span would fuse with the next one
    longest = _longest("`", text)
    if longest >= _MAX_SPAN_FENCE:
        return md_text(text)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def md_block(text: str) -> str:
    """*text* as one fenced Markdown code block, its lines kept and controls escaped.

    The fence outruns every backtick run, or every tilde run when no backtick fence
    cmark-gfm opens is long enough; when neither is, the text falls back to :func:`md_text`.
    """
    text = printable_lines(text)
    for char in "`~":
        longest = _longest(char, text)
        if longest < _MAX_BLOCK_FENCE:
            fence = char * max(3, longest + 1)
            return f"{fence}\n{text}\n{fence}"
    return md_text(text)
