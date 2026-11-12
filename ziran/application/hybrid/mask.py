"""Secret masking for the hybrid's request texts (spec 067).

The token rules of ziran-paper ``annotation/mask.py`` (the study's registered mask and masking
change 1, at e4b2025): SA001's values, the token prefixes and JWTs, each span shown as ``***``
after overlapping spans are joined. PEM private key blocks are added here; the study catches them
with its pinned gitleaks scan, which ziran does not run. The structured-file and name rules of
``mask.py`` are not ported: a request holds rendered text, not a config file.
"""

from __future__ import annotations

import re

MASK = "***"

# mask.SA001: ziran's SA001 patterns at b813e4f
_SA001 = tuple(
    re.compile(p)
    for p in (
        r"(?i)(api[_-]?key|secret[_-]?key|password|token|credential)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        r"(?i)(aws_secret|aws_access_key|openai_api_key)\s*[:=]\s*['\"][^'\"]+['\"]",
        r"sk-[a-zA-Z0-9]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"(?i)Bearer\s+[a-zA-Z0-9\-._~+/]+=*",
    )
)


def _prefix(prefixes: tuple[str, ...], tail: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![A-Za-z0-9])(?:{'|'.join(map(re.escape, prefixes))}){tail}")


_TOKENS = (
    # mask.REGISTERED_PREFIX
    _prefix(("ghp_", "gho_", "github_pat_", "sk-", "AIza", "xox"), r"[^\s'\"/?&#]*"),
    # mask.CHANGE_PREFIX
    _prefix(
        (
            "sk_live_",
            "sk_test_",
            "rk_live_",
            "glpat-",
            "ghs_",
            "ghu_",
            "ghr_",
            "hf_",
            "tvly-",
            "npm_",
            "pypi-",
        ),
        r"(?=[A-Za-z0-9_\-]*[A-Z0-9])[A-Za-z0-9_\-]{16,}",
    ),
    # mask.JWT
    re.compile(r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?"),
    # a PEM private key, to its END line or, cut short, to the end of the text
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY-----|.*)", re.S
    ),
)


def _sa001_values(text: str) -> list[tuple[int, int]]:
    """mask.sa001_value_spans: only the value part of an SA001 match."""
    spans = []
    for pattern in _SA001:
        for m in pattern.finditer(text):
            s, e = m.span()
            quote = re.search(r"['\"]", m.group())
            bearer = re.match(r"(?i)bearer\s+", m.group())
            if quote:
                spans.append((s + quote.end(), e - 1))
            elif bearer:
                spans.append((s + bearer.end(), e))
            else:
                spans.append((s, e))
    return spans


def mask(text: str) -> str:
    """``text`` with every secret span, joined with any it overlaps, shown as ``***``."""
    spans = _sa001_values(text) + [m.span() for p in _TOKENS for m in p.finditer(text)]
    merged: list[list[int]] = []
    for s, e in sorted(sp for sp in spans if sp[1] > sp[0]):
        if merged and s < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out, last = [], 0
    for s, e in merged:
        out += [text[last:s], MASK]
        last = e
    return "".join([*out, text[last:]])
