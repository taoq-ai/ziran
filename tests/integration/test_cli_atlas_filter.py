"""Integration tests for the ``ziran library --atlas`` CLI flag.

Rich table output truncates long columns in narrow test terminals, so these
tests assert on filter behavior via the count line ("Attack Library (N
vectors)") and via exit codes rather than trying to match specific technique
IDs in the rendered table.
"""

from __future__ import annotations

import re

import pytest
from click.testing import CliRunner

from ziran.interfaces.cli.main import cli

_COUNT_RE = re.compile(r"Attack Library \((\d+) vectors\)")


def _extract_count(output: str) -> int:
    match = _COUNT_RE.search(output)
    assert match is not None, f"Could not find vector count in output:\n{output[:500]}"
    return int(match.group(1))


@pytest.mark.integration
def test_valid_atlas_technique_returns_non_empty() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["library", "--atlas", "AML.T0051"])
    assert result.exit_code == 0, result.output
    assert "ATLAS" in result.output
    assert _extract_count(result.output) > 0


@pytest.mark.integration
def test_invalid_atlas_technique_errors_with_suggestion() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["library", "--atlas", "AML.T0050X"])
    assert result.exit_code != 0
    assert "Unknown ATLAS technique" in result.output


@pytest.mark.integration
def test_atlas_and_owasp_filters_compose_as_and() -> None:
    runner = CliRunner()
    atlas_only = runner.invoke(cli, ["library", "--atlas", "AML.T0051.000"])
    combined = runner.invoke(
        cli, ["library", "--atlas", "AML.T0051.000", "--owasp", "LLM01"]
    )
    assert atlas_only.exit_code == 0
    assert combined.exit_code == 0
    # AND semantics: combined count must not exceed the single-filter count.
    assert _extract_count(combined.output) <= _extract_count(atlas_only.output)
    assert _extract_count(combined.output) > 0


@pytest.mark.integration
def test_library_listing_includes_atlas_column() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["library", "--category", "prompt_injection"])
    assert result.exit_code == 0
    # The ATLAS column header appears in the Rich table.
    assert "ATLAS" in result.output
