"""Typosquat detection for MCP server and tool names.

Uses Levenshtein distance and common character-substitution patterns
to flag names that are suspiciously close to known-good entries in
the allowlist.
"""

from __future__ import annotations

from ziran.domain.entities.registry import DriftFinding

# Common substitution pairs used in typosquatting attacks.
# Each tuple is (original_substring, substitution_substring).
_SUBSTITUTION_PAIRS: list[tuple[str, str]] = [
    ("l", "1"),
    ("o", "0"),
    ("rn", "m"),
    ("i", "1"),
    ("s", "5"),
    ("e", "3"),
    ("a", "@"),
    ("g", "q"),
    ("cl", "d"),
    ("vv", "w"),
]


def _levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        return _levenshtein(b, a)

    if len(b) == 0:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr_row = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr_row.append(
                min(
                    prev_row[j + 1] + 1,  # deletion
                    curr_row[j] + 1,  # insertion
                    prev_row[j] + cost,  # substitution
                )
            )
        prev_row = curr_row
    return prev_row[-1]


def _has_substitution(name: str, canonical: str) -> bool:
    """Check if *name* looks like a character-substitution attack on *canonical*."""
    name_lower = name.lower()
    canonical_lower = canonical.lower()

    for original, substitute in _SUBSTITUTION_PAIRS:
        # Try replacing in canonical to see if it produces the suspect name
        if canonical_lower.replace(original, substitute) == name_lower:
            return True
        # Also try reverse direction
        if name_lower.replace(substitute, original) == canonical_lower:
            return True
    return False


def detect(
    name: str,
    allowlist: list[str],
    exemptions: list[str] | None = None,
) -> list[DriftFinding]:
    """Detect potential typosquats of *name* against an *allowlist*.

    Args:
        name: The server or tool name to check.
        allowlist: Known-good names to compare against.
        exemptions: Names to skip (never flag as typosquats).

    Returns:
        List of ``DriftFinding`` objects for each suspected match.
    """
    exemptions = exemptions or []
    if name in exemptions:
        return []

    findings: list[DriftFinding] = []
    for canonical in allowlist:
        if name == canonical:
            continue

        distance = _levenshtein(name, canonical)
        is_sub = _has_substitution(name, canonical)

        if distance <= 2 or is_sub:
            severity = "high" if distance == 1 or is_sub else "medium"

            findings.append(
                DriftFinding(
                    server_name=name,
                    drift_type="typosquat",
                    severity=severity,
                    tool_name=None,
                    suspected_canonical=canonical,
                    message=(
                        f"Name '{name}' is suspiciously similar to '{canonical}' "
                        f"(edit distance={distance}, substitution={is_sub})"
                    ),
                )
            )

    return findings
