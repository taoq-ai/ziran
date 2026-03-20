"""Architecture validation tests for the agent_scanner package.

Ensures the refactoring stays within size limits and that scanner.py
imports from its sub-modules rather than re-implementing logic inline.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_AGENT_SCANNER_DIR = Path(__file__).resolve().parents[3] / "ziran" / "application" / "agent_scanner"
_SCANNER_PY = _AGENT_SCANNER_DIR / "scanner.py"


@pytest.mark.unit
class TestScannerSize:
    """Validate that scanner.py stays within the target line budget."""

    def test_scanner_under_700_lines(self) -> None:
        line_count = len(_SCANNER_PY.read_text().splitlines())
        assert line_count <= 700, (
            f"scanner.py has {line_count} lines, which exceeds the 700-line target. "
            "Consider extracting more logic into sub-modules."
        )


@pytest.mark.unit
class TestSubModuleSizes:
    """Validate that no sub-module in agent_scanner/ exceeds 400 lines."""

    def test_no_module_exceeds_400_lines(self) -> None:
        violations: list[str] = []
        for py_file in _AGENT_SCANNER_DIR.glob("*.py"):
            if py_file.name == "__init__.py":
                continue
            if py_file.name == "scanner.py":
                continue
            line_count = len(py_file.read_text().splitlines())
            if line_count > 400:
                violations.append(f"{py_file.name}: {line_count} lines")

        assert not violations, f"Sub-modules exceeding 400-line limit: {', '.join(violations)}"


@pytest.mark.unit
class TestScannerImportsSubModules:
    """Verify that scanner.py imports from its sub-modules using AST analysis."""

    @pytest.fixture(scope="class")
    def scanner_imports(self) -> set[str]:
        """Parse scanner.py and collect all imported module paths."""
        tree = ast.parse(_SCANNER_PY.read_text())
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
        return modules

    def test_imports_progress_module(self, scanner_imports: set[str]) -> None:
        assert "ziran.application.agent_scanner.progress" in scanner_imports

    def test_imports_attack_executor_module(self, scanner_imports: set[str]) -> None:
        assert "ziran.application.agent_scanner.attack_executor" in scanner_imports

    def test_imports_phase_executor_module(self, scanner_imports: set[str]) -> None:
        assert "ziran.application.agent_scanner.phase_executor" in scanner_imports

    def test_imports_result_builder_module(self, scanner_imports: set[str]) -> None:
        assert "ziran.application.agent_scanner.result_builder" in scanner_imports
