"""Unit tests: the pattern matcher matches whole words (spec 099, change 9, A5)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml

from ziran.application.knowledge_graph.chain_analyzer import ToolChainAnalyzer
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit

matches = ToolChainAnalyzer._pattern_matches
keywords = ToolChainAnalyzer._to_keywords


def test_a_tool_word_inside_a_pattern_word_does_not_match() -> None:
    tool = "mcp__x__add_to_list"  # `to` is inside `directory`
    assert not matches("list_directory", tool, keywords(tool))
    assert not matches("git_commit", "it", {"it"})


def test_a_pattern_word_inside_a_tool_word_still_matches() -> None:
    assert matches("read_file", "fs_read_file", keywords("fs_read_file"))  # substring
    assert matches(
        "http_request", "requests_http", keywords("requests_http")
    )  # request in requests
    assert matches("read_file", "file_reader", keywords("file_reader"))  # read in reader


def _pattern(source: str, target: str, kind: str, risk: str) -> dict[str, str]:
    return {
        "source": source,
        "target": target,
        "type": kind,
        "risk": risk,
        "category": "test",
        "description": "d",
    }


@pytest.mark.parametrize("flip", [False, True])
def test_two_patterns_on_one_pair_give_one_type_whichever_comes_first(
    tmp_path: Path, flip: bool
) -> None:
    patterns = [
        _pattern("zzfetch", "zzmail", "general_type", "critical"),
        _pattern("zzfetch_record", "zzmail_out", "specific_type", "high"),
    ]
    path = tmp_path / "patterns.yaml"
    path.write_text(yaml.safe_dump({"patterns": patterns[::-1] if flip else patterns}))
    analyzer = ToolChainAnalyzer(AttackKnowledgeGraph(), custom_patterns_path=path)
    info = analyzer._match_pattern("zzfetch_record", "zzmail_out", {})
    assert info is not None and info["type"] == "specific_type"  # the longer pattern wins
    info = analyzer._match_pattern("zzfetch_log", "zzmail_now", {})
    assert info is not None and info["type"] == "general_type"
