"""Tests for pre-compiled regex patterns in static analysis config models."""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest

from ziran.application.static_analysis.config import (
    CheckDefinition,
    DangerousToolCheck,
    InputValidationCheck,
    PatternRule,
    StaticAnalysisConfig,
)


class TestPatternRuleCompilation:
    """T001: PatternRule compiles pattern eagerly at construction."""

    def test_pattern_rule_has_compiled_field(self) -> None:
        rule = PatternRule(pattern=r"\bsecret\b", description="test")
        assert isinstance(rule.compiled, re.Pattern)

    def test_pattern_rule_compiled_matches(self) -> None:
        rule = PatternRule(pattern=r"\bsecret\b")
        assert rule.compiled.search("my secret key")
        assert not rule.compiled.search("no match here")

    def test_invalid_pattern_raises_at_construction(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            PatternRule(pattern=r"[invalid")


class TestCheckDefinitionCompilation:
    """T002: CheckDefinition exposes compiled_patterns property."""

    def test_compiled_patterns_returns_list(self) -> None:
        check = CheckDefinition(
            check_id="SA001",
            message="test",
            severity="high",
            patterns=[
                PatternRule(pattern=r"\bfoo\b"),
                PatternRule(pattern=r"\bbar\b"),
            ],
        )
        compiled = check.compiled_patterns
        assert len(compiled) == 2
        assert all(isinstance(p, re.Pattern) for p in compiled)

    def test_compiled_patterns_empty_when_no_patterns(self) -> None:
        check = CheckDefinition(check_id="SA001", message="test", severity="low")
        assert check.compiled_patterns == []

    def test_compiled_patterns_match_correctly(self) -> None:
        check = CheckDefinition(
            check_id="SA001",
            message="test",
            severity="high",
            patterns=[PatternRule(pattern=r"api[_-]?key")],
        )
        assert check.compiled_patterns[0].search("my_api_key = 'abc'")


class TestDangerousToolCheckCompilation:
    """T003: DangerousToolCheck compiles pattern eagerly."""

    def test_has_compiled_pattern(self) -> None:
        check = DangerousToolCheck(pattern=r"\bexec\b", description="exec call")
        assert isinstance(check.compiled_pattern, re.Pattern)

    def test_compiled_pattern_matches(self) -> None:
        check = DangerousToolCheck(pattern=r"\bexec\b", description="exec call")
        assert check.compiled_pattern.search("exec('code')")
        assert not check.compiled_pattern.search("execute('code')")

    def test_invalid_pattern_raises(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            DangerousToolCheck(pattern=r"[bad", description="bad")


class TestInputValidationCheckCompilation:
    """T004: InputValidationCheck compiles both patterns eagerly."""

    def test_has_compiled_tool_pattern(self) -> None:
        check = InputValidationCheck()
        assert isinstance(check.compiled_tool_pattern, re.Pattern)

    def test_has_compiled_validation_pattern(self) -> None:
        check = InputValidationCheck()
        assert isinstance(check.compiled_validation_pattern, re.Pattern)

    def test_tool_pattern_matches_default(self) -> None:
        check = InputValidationCheck()
        assert check.compiled_tool_pattern.search("@tool")

    def test_validation_pattern_matches_default(self) -> None:
        check = InputValidationCheck()
        assert check.compiled_validation_pattern.search("validate(input)")


class TestNoRuntimeCompilation:
    """T006: Verify no re.compile() during analysis."""

    def test_run_check_does_not_call_compile(self) -> None:
        from ziran.application.static_analysis.analyzer import _run_check

        check = CheckDefinition(
            check_id="SA001",
            message="test",
            severity="high",
            patterns=[PatternRule(pattern=r"\bsecret\b")],
        )
        lines = ["secret = 'abc'", "normal line"]

        with patch("re.compile", side_effect=AssertionError("re.compile called")) as mock:
            # _run_check should NOT call re.compile — it uses pre-compiled patterns
            # We need to be careful: the check object already has compiled patterns
            # so _run_check should just use them
            findings = _run_check(check, lines, "test.py")
            mock.assert_not_called()
        assert len(findings) == 1

    def test_run_dangerous_tool_checks_does_not_call_compile(self) -> None:
        from ziran.application.static_analysis.analyzer import _run_dangerous_tool_checks

        checks = [DangerousToolCheck(pattern=r"\bexec\b", description="exec")]
        lines = ["exec('code')"]

        with patch("re.compile", side_effect=AssertionError("re.compile called")) as mock:
            findings = _run_dangerous_tool_checks(checks, lines, "test.py")
            mock.assert_not_called()
        assert len(findings) == 1

    def test_check_input_validation_does_not_call_compile(self) -> None:
        from ziran.application.static_analysis.analyzer import _check_input_validation

        check = InputValidationCheck()
        content = "@tool\ndef my_tool() -> str:\n    return 'result'"

        with patch("re.compile", side_effect=AssertionError("re.compile called")) as mock:
            findings = _check_input_validation(check, content, "test.py")
            mock.assert_not_called()
        assert len(findings) == 1  # no validation detected


class TestConfigMergingPreservesCompilation:
    """Verify compiled patterns survive config merging."""

    def test_merged_config_has_compiled_patterns(self) -> None:
        config1 = StaticAnalysisConfig(
            secret_checks=[
                CheckDefinition(
                    check_id="SA001",
                    message="secrets",
                    severity="critical",
                    patterns=[PatternRule(pattern=r"\bapi_key\b")],
                )
            ]
        )
        config2 = StaticAnalysisConfig(
            secret_checks=[
                CheckDefinition(
                    check_id="SA099",
                    message="custom",
                    severity="high",
                    patterns=[PatternRule(pattern=r"\btoken\b")],
                )
            ]
        )
        merged = config1.merge(config2)
        assert len(merged.secret_checks) == 2
        for check in merged.secret_checks:
            for p in check.patterns:
                assert isinstance(p.compiled, re.Pattern)
