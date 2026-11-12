"""Prompt registry tests (spec 064)."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from ziran.application.hybrid.prompts import PROMPTS, Prompt, load

FIXTURES = Path(__file__).parents[1] / "fixtures" / "hybrid_prompts"
REPO = Path(__file__).parents[2]
BASE = "origin/develop"


@pytest.mark.unit
@pytest.mark.parametrize("job", ["trace_judge", "capability", "plausibility"])
def test_load_gives_text_and_sha256_of_the_bytes(job: str) -> None:
    path = FIXTURES / job / "v0.md"
    prompt = load(job, 0, root=FIXTURES)
    assert prompt == Prompt(
        job=job,
        version=0,
        text=path.read_text(encoding="utf-8"),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("job", "version"),
    [("../trace_judge", 0), ("", 0), ("Trace", 0), ("trace_judge/..", 0), ("trace_judge", -1)],
)
def test_names_that_could_leave_the_folder_are_refused(job: str, version: int) -> None:
    with pytest.raises(ValueError, match="prompt"):
        load(job, version, root=FIXTURES)


@pytest.mark.unit
def test_bool_version_is_refused() -> None:
    with pytest.raises(ValueError, match="prompt"):
        load("trace_judge", True, root=FIXTURES)


@pytest.mark.unit
def test_missing_version_raises_file_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        load("trace_judge", 9, root=FIXTURES)


@pytest.mark.unit
def test_the_shipped_folder_is_the_package_prompts_folder() -> None:
    assert Path("ziran/application/hybrid/prompts") == PROMPTS.relative_to(REPO)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)


def _edited(repo: Path, base: str) -> list[str]:
    """Prompt files on ``base`` that differ at the work tree or are gone."""
    folder = "ziran/application/hybrid/prompts"
    listed = _git(repo, "ls-tree", "-r", "-z", "--name-only", base, "--", folder)
    assert listed.returncode == 0, listed.stderr
    out = []
    for name in filter(None, listed.stdout.decode().split("\0")):
        old = _git(repo, "show", f"{base}:{name}")
        assert old.returncode == 0, old.stderr
        new = repo / name
        if not new.is_file() or new.read_bytes() != old.stdout:
            out.append(name)
    return out


@pytest.mark.unit
def test_a_merged_prompt_version_is_never_edited_or_removed() -> None:
    """Every prompt file on the base branch is byte-equal at the head (CI fetches develop)."""
    if _git(REPO, "rev-parse", "--verify", "--quiet", f"{BASE}^{{commit}}").returncode != 0:
        pytest.skip(f"{BASE} is not fetched; the CI test job fetches it")
    assert _edited(REPO, BASE) == [], "merged prompt versions edited or removed; add v<N+1>"


@pytest.mark.unit
def test_the_immutability_check_catches_an_edit_and_a_removal(tmp_path: Path) -> None:
    folder = tmp_path / "ziran" / "application" / "hybrid" / "prompts" / "trace_judge"
    folder.mkdir(parents=True)
    (folder / "v0.md").write_text("zero\n")
    (folder / "v1.md").write_text("one\n")
    who = ("-c", "user.name=t", "-c", "user.email=t@example.invalid")
    for step in (("init", "-q"), ("add", "."), (*who, "commit", "-q", "-m", "base")):
        assert _git(tmp_path, *step).returncode == 0
    assert _edited(tmp_path, "HEAD") == []
    (folder / "v2.md").write_text("two\n")  # a new version is allowed
    assert _edited(tmp_path, "HEAD") == []
    (folder / "v0.md").write_text("zero!\n")
    (folder / "v1.md").unlink()
    assert _edited(tmp_path, "HEAD") == [
        "ziran/application/hybrid/prompts/trace_judge/v0.md",
        "ziran/application/hybrid/prompts/trace_judge/v1.md",
    ]
