"""Unit tests for Static Agent Configuration Analysis (Feature 6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from koan.application.static_analysis.analyzer import (
    AnalysisReport,
    StaticAnalyzer,
    StaticFinding,
)


@pytest.fixture()
def analyzer() -> StaticAnalyzer:
    return StaticAnalyzer()


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _write_file(tmp_path: Path, content: str, name: str = "agent.py") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


# ──────────────────────────────────────────────────────────────────────
# SA001 — Secrets in source code
# ──────────────────────────────────────────────────────────────────────


class TestSecretDetection:
    def test_api_key_in_code(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            'api_key = "sk-abc123456789012345678901234567890123"\n',
        )
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA001" for f in findings)

    def test_aws_key_detected(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            'aws_access_key = "AKIAIOSFODNN7EXAMPLE"\n',
        )
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA001" for f in findings)

    def test_no_secret_clean(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            'api_key = os.environ["API_KEY"]\n',
        )
        findings = analyzer.analyze_file(src)
        assert not any(f.check_id == "SA001" for f in findings)


# ──────────────────────────────────────────────────────────────────────
# SA003 — Dangerous tool permissions
# ──────────────────────────────────────────────────────────────────────


class TestDangerousTools:
    def test_subprocess_detected(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            "import subprocess\nresult = subprocess.run(['ls'])\n",
        )
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA003" for f in findings)

    def test_os_system_detected(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(tmp_path, 'os.system("rm -rf /")\n')
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA003" for f in findings)

    def test_eval_detected(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(tmp_path, "result = eval(user_input)\n")
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA003" for f in findings)

    def test_file_write_detected(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(tmp_path, "write_file(path, content)\n")
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA003" for f in findings)


# ──────────────────────────────────────────────────────────────────────
# SA008 — Hard-coded credentials
# ──────────────────────────────────────────────────────────────────────


class TestHardcodedCredentials:
    def test_password_in_code(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(tmp_path, 'password = "SuperSecret123"\n')
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA008" for f in findings)

    def test_db_password(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(tmp_path, 'db_password = "my_database_pass_12345"\n')
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA008" for f in findings)


# ──────────────────────────────────────────────────────────────────────
# SA009 — SQL injection risk
# ──────────────────────────────────────────────────────────────────────


class TestSQLInjection:
    def test_fstring_in_execute(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n',
        )
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA009" for f in findings)

    def test_string_concat_in_execute(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            'cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n',
        )
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA009" for f in findings)


# ──────────────────────────────────────────────────────────────────────
# SA010 — PII exposure
# ──────────────────────────────────────────────────────────────────────


class TestPIIExposure:
    def test_ssn_field(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            'record = {"name": "Alice", "ssn": "412-55-7890"}\n',
        )
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA010" for f in findings)

    def test_ssn_pattern(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            'value = "412-55-7890"\n',
        )
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA010" for f in findings)


# ──────────────────────────────────────────────────────────────────────
# SA002 — No input validation
# ──────────────────────────────────────────────────────────────────────


class TestInputValidation:
    def test_tool_without_validation(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            "@tool\ndef lookup(query: str) -> str:\n    return db.get(query)\n",
        )
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA002" for f in findings)

    def test_tool_with_validation(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            '@tool\ndef lookup(query: str) -> str:\n    if not query.strip():\n        raise ValueError("empty")\n    return db.get(query)\n',
        )
        findings = analyzer.analyze_file(src)
        assert not any(f.check_id == "SA002" for f in findings)


# ──────────────────────────────────────────────────────────────────────
# SA006 — Verbose errors
# ──────────────────────────────────────────────────────────────────────


class TestVerboseErrors:
    def test_traceback_format_exc(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        src = _write_file(
            tmp_path,
            "import traceback\nerr = traceback.format_exc()\n",
        )
        findings = analyzer.analyze_file(src)
        assert any(f.check_id == "SA006" for f in findings)


# ──────────────────────────────────────────────────────────────────────
# Directory scanning
# ──────────────────────────────────────────────────────────────────────


class TestDirectoryAnalysis:
    def test_analyze_directory(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text('password = "secret123"\n')
        (tmp_path / "utils.py").write_text("x = 1\n")
        report = analyzer.analyze_directory(tmp_path)
        assert report.files_analyzed == 2
        assert report.total_issues >= 1

    def test_empty_directory(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        report = analyzer.analyze_directory(tmp_path)
        assert report.files_analyzed == 0
        assert report.passed

    def test_skips_pycache(self, analyzer: StaticAnalyzer, tmp_path: Path) -> None:
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "bad.py").write_text('password = "secret"\n')
        report = analyzer.analyze_directory(tmp_path)
        assert report.files_analyzed == 0


# ──────────────────────────────────────────────────────────────────────
# AnalysisReport properties
# ──────────────────────────────────────────────────────────────────────


class TestAnalysisReport:
    def test_empty_report_passes(self) -> None:
        report = AnalysisReport()
        assert report.passed
        assert report.total_issues == 0

    def test_critical_fails(self) -> None:
        report = AnalysisReport(
            findings=[
                StaticFinding(
                    check_id="SA001",
                    message="secret found",
                    severity="critical",
                    file_path="test.py",
                )
            ]
        )
        assert not report.passed
        assert report.critical_count == 1

    def test_high_still_passes(self) -> None:
        report = AnalysisReport(
            findings=[
                StaticFinding(
                    check_id="SA003",
                    message="dangerous tool",
                    severity="high",
                    file_path="test.py",
                )
            ]
        )
        assert report.passed  # only critical causes failure
        assert report.high_count == 1


# ──────────────────────────────────────────────────────────────────────
# Nonexistent / unreadable files
# ──────────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_nonexistent_file(self, analyzer: StaticAnalyzer) -> None:
        findings = analyzer.analyze_file(Path("/nonexistent/agent.py"))
        assert findings == []

    def test_finding_fields(self) -> None:
        f = StaticFinding(
            check_id="SA001",
            message="test",
            severity="critical",
            file_path="x.py",
            line_number=42,
            context="line content",
            recommendation="fix it",
        )
        assert f.line_number == 42
        assert f.recommendation == "fix it"
