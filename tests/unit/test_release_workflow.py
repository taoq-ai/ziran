"""Contract test for the release workflow's attestation path (spec 095)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW = yaml.safe_load(
    (Path(__file__).parents[2] / ".github" / "workflows" / "release.yml").read_text()
)
JOBS: dict[str, Any] = WORKFLOW["jobs"]
PINNED = re.compile(r"^actions/(download-artifact|attest)@[0-9a-f]{40}$")

pytestmark = pytest.mark.unit


def _with(job: str, action: str) -> list[dict[str, Any]]:
    return [s.get("with", {}) for s in JOBS[job]["steps"] if s.get("uses", "").startswith(action)]


def test_attest_job_holds_only_the_scopes_it_needs() -> None:
    assert JOBS["attest"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }
    assert JOBS["attest"]["needs"] == ["build"]


def test_attest_job_runs_no_build_code() -> None:
    steps = JOBS["attest"]["steps"]
    assert all("run" not in s for s in steps)
    assert all(PINNED.match(s["uses"]) for s in steps), [s["uses"] for s in steps]


def test_attest_job_attests_provenance_and_sbom() -> None:
    provenance, sbom = _with("attest", "actions/attest@")
    assert provenance["subject-path"].split() == ["dist/*", "sbom/*.cdx.json"]
    assert "sbom-path" not in provenance
    assert sbom["subject-path"] == "dist/*"
    assert sbom["sbom-path"].startswith("sbom/") and sbom["sbom-path"].endswith(".cdx.json")


def test_nothing_publishes_before_attestation() -> None:
    for job in ("publish-pypi", "publish-testpypi"):
        assert "attest" in JOBS[job]["needs"], job


def test_build_exports_cyclonedx_sbom() -> None:
    [run] = [s["run"] for s in JOBS["build"]["steps"] if "uv export" in s.get("run", "")]
    assert "--format cyclonedx1.5" in run
    assert "--frozen" in run and "--no-default-groups" in run and "--all-extras" in run
    assert [w["name"] for w in _with("build", "actions/upload-artifact@")] == ["dist", "sbom"]


def test_github_release_attaches_sbom() -> None:
    assert {w["name"] for w in _with("github-release", "actions/download-artifact@")} == {
        "dist",
        "sbom",
    }
    [files] = [w["files"] for w in _with("github-release", "softprops/action-gh-release@")]
    assert files.split() == ["dist/*", "sbom/*.cdx.json"]


def test_security_policy_shows_how_to_verify() -> None:
    policy = (Path(__file__).parents[2] / "SECURITY.md").read_text()
    for heading in ("Supported versions", "Reporting a vulnerability", "Verifying a release"):
        assert f"\n## {heading}\n" in policy, heading
    assert "attestation verify" in policy and "--repo taoq-ai/ziran" in policy
