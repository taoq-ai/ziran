"""Sigma rules as plain data: the schema's structural rules and a matcher (spec 120).

``sigma_schema_errors`` holds the required fields and value rules of the Sigma v2 detection and
correlation JSON schemas. ``sigma_matches`` evaluates the subset ZIRAN writes (field maps, value
lists, wildcards, ``and`` / ``not`` conditions, ``temporal`` correlations) on span attribute maps.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

__all__ = ["LEVELS", "TAG", "event_matches", "sigma_matches", "sigma_schema_errors"]

LEVELS = ("informational", "low", "medium", "high", "critical")
_STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
#: The schema's tag pattern; ``fullmatch`` it, as ``$`` would let a trailing newline through.
TAG = re.compile(r"[a-z0-9_-]+\.[a-z0-9._-]+")


def sigma_schema_errors(doc: Mapping[str, Any]) -> list[str]:
    """Breaks of the Sigma v2 detection or correlation JSON schema's rules, for one rule."""
    errors: list[str] = []
    title = doc.get("title")
    if not isinstance(title, str) or not title or len(title) > 256:
        errors.append("title must be a string of 1 to 256 characters")
    if "id" in doc:
        try:
            uuid.UUID(str(doc["id"]))
        except ValueError:
            errors.append("id must be a UUID")
    if "status" in doc and doc["status"] not in _STATUSES:
        errors.append(f"status must be one of {_STATUSES}")
    if "level" in doc and doc["level"] not in LEVELS:
        errors.append(f"level must be one of {LEVELS}")
    tags = doc.get("tags", [])
    if not isinstance(tags, list) or len(set(tags)) != len(tags):
        errors.append("tags must be a list of unique values")
    elif any(not isinstance(t, str) or not TAG.fullmatch(t) for t in tags):
        errors.append("tags must match namespace.value in lower case")
    for key in ("references", "falsepositives"):
        values = doc.get(key, [])
        if not isinstance(values, list) or len(set(map(str, values))) != len(values):
            errors.append(f"{key} must be a list of unique values")
    if "correlation" in doc:
        corr = doc["correlation"]
        for key in ("type", "rules", "timespan", "group-by"):
            if key not in corr:
                errors.append(f"correlation needs {key}")
        if not re.fullmatch(r"\d+[smhdwMy]", str(corr.get("timespan", ""))):
            errors.append("correlation timespan must be a number and a unit")
        return errors
    source = doc.get("logsource")
    if not isinstance(source, dict) or not {"category", "product", "service"} & set(source):
        errors.append("logsource needs a category, product or service")
    detection = doc.get("detection")
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str):
        errors.append("detection needs a condition")
    return errors


def _value_matches(expected: Any, actual: Any) -> bool:
    """Sigma string match: case-insensitive, ``*`` and ``?`` wildcards, ``\\`` escapes.

    A greedy walk that backs up only to the last ``*``: O(len(pattern) * len(value)) at worst,
    where a regex of many ``.*`` backtracks exponentially on a value that does not match.
    """
    if actual is None:
        return False
    parts = re.findall(r"\\[*?\\]|.", str(expected), re.DOTALL)
    text = str(actual)
    p = t = 0
    star, mark = -1, 0
    while t < len(text):
        if p < len(parts) and parts[p] == "*":
            star, mark = p, t
            p += 1
        elif p < len(parts) and (parts[p] == "?" or parts[p][-1].lower() == text[t].lower()):
            p += 1
            t += 1
        elif star >= 0:
            mark += 1
            p, t = star + 1, mark
        else:
            return False
    return all(part == "*" for part in parts[p:])


def event_matches(rule: Mapping[str, Any], span: Mapping[str, Any]) -> bool:
    # ponytail: only the "a and not b" conditions and plain field maps this renderer writes
    detection = rule["detection"]
    for term in str(detection["condition"]).split(" and "):
        negate = term.startswith("not ")
        selection = detection[term.removeprefix("not ")]
        hit = all(
            any(_value_matches(v, span.get(field)) for v in (vs if isinstance(vs, list) else [vs]))
            for field, vs in selection.items()
        )
        if hit == negate:
            return False
    return True


def sigma_matches(content: str, spans: Sequence[Mapping[str, Any]]) -> bool:
    """Whether the file's top rule fires on *spans* (attribute maps, ``time`` in seconds).

    The top rule is the correlation, or the single rule of a one-tool chain.
    """
    docs = [d for d in yaml.safe_load_all(content) if d]
    corr = next((d for d in docs if "correlation" in d), None)
    if corr is None:
        return any(event_matches(docs[0], s) for s in spans)
    spec = corr["correlation"]
    rules = [next(d for d in docs if d.get("name") == n) for n in spec["rules"]]
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[spec["timespan"][-1]]
    window = int(spec["timespan"][:-1]) * unit
    groups: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for span in spans:
        groups[tuple(span.get(f) for f in spec["group-by"])].append(span)
    return any(
        all(
            any(event_matches(r, s) for s in group if 0 <= s["time"] - start["time"] <= window)
            for r in rules
        )
        for group in groups.values()
        for start in group
    )
