"""Contract test for the composite GitHub Action (spec 040).

WUWEI and other consumers pin the action's input/output names and defaults.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

ACTION = yaml.safe_load((Path(__file__).parents[2] / "action.yml").read_text())

pytestmark = pytest.mark.unit


def _step(step_id: str) -> dict[str, Any]:
    [step] = [s for s in ACTION["runs"]["steps"] if s.get("id") == step_id]
    return step


def test_input_defaults() -> None:
    defaults = {k: v["default"] for k, v in ACTION["inputs"].items()}
    assert (
        defaults
        | {
            "command": "ci",
            "result-file": "",
            "source-path": ".",
            "path": "",
            "baseline": "",
            "sarif-output": "ziran-results.sarif",
            "severity-threshold": "low",
            "python-version": "3.12",
            "ziran-version": "ziran",
        }
        == defaults
    )


def test_outputs() -> None:
    values = {k: v["value"] for k, v in ACTION["outputs"].items()}
    assert values == {
        "status": "${{ steps.run.outputs.status }}",
        "trust-score": "${{ steps.run.outputs.trust_score }}",
        "total-findings": "${{ steps.run.outputs.total_findings }}",
        "critical-findings": "${{ steps.run.outputs.critical_findings }}",
        "sarif-file": "${{ steps.run.outputs.sarif_file }}",
        "exit-code": "${{ steps.run.outputs.exit_code }}",
        "sarif-id": "${{ steps.upload.outputs.sarif-id }}",
    }


def test_run_env_and_audit_branch() -> None:
    run = _step("run")
    assert run["env"] == {
        "ZIRAN_INPUT_PATH": "${{ inputs.path }}",
        "ZIRAN_INPUT_SOURCE_PATH": "${{ inputs.source-path }}",
        "ZIRAN_INPUT_BASELINE": "${{ inputs.baseline }}",
        "ZIRAN_INPUT_SEVERITY": "${{ inputs.severity-threshold }}",
        "ZIRAN_INPUT_SARIF": "${{ inputs.sarif-output }}",
    }
    script: str = run["run"]
    audit = script.split("  audit)\n", 1)[1].split(";;", 1)[0]
    assert "${{ inputs." not in audit
    assert 'ziran audit "${AUDIT_ARGS[@]}"' in audit
    assert 'echo "exit_code=$EXIT_CODE"' in script


def test_upload_step_has_id() -> None:
    assert _step("upload")["uses"].startswith("github/codeql-action/upload-sarif@")
