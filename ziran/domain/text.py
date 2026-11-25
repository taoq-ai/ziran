"""Target text shown to a person: one line, no live control character."""

from __future__ import annotations


def printable(value: str) -> str:
    """``value`` with every non-printable character (C0, C1, ESC, bidi) backslash-escaped.

    A newline becomes ``\\n``, so the value stays on one line in a table row or a terminal.
    """
    return "".join(
        c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in value
    )
