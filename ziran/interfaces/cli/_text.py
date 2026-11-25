"""Target text in a Rich string or table cell: controls escaped, markup inert."""

from __future__ import annotations

from rich.markup import escape

from ziran.domain.text import printable


def term(value: object) -> str:
    """*value* for a Rich string: controls and bidi backslash-escaped, markup shown as text."""
    return escape(printable(str(value)))
