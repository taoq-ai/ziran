"""Run conditions: interpreter flags, environment, pins and the harness record (sections 4, 9)."""

from __future__ import annotations

import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
from importlib import metadata
from typing import TYPE_CHECKING, Any

from benchmarks.external_eval.intake import HarnessError

if TYPE_CHECKING:
    from collections.abc import MutableMapping
    from pathlib import Path

#: The seven files protocol section 1 pins, hashed at each pin with the pin's uv.lock.
PINNED_FILES = (
    "ziran/application/detectors/pipeline.py",
    "ziran/application/detectors/refusal.py",
    "ziran/application/detectors/indicator.py",
    "ziran/application/detectors/side_effect.py",
    "ziran/application/detectors/authorization.py",
    "ziran/application/detectors/thresholds.py",
    "ziran/domain/tool_classifier.py",
    "uv.lock",
)
HARNESS_DIR = "benchmarks/external_eval"
_SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH|COOKIE|SESSION", re.IGNORECASE)


def require_interpreter_flags() -> None:
    """``python -I`` and not ``-O``: the InjecAgent parser signals failure with assert."""
    if not sys.flags.isolated:
        raise HarnessError("run the harness with python -I")
    if sys.flags.optimize:
        raise HarnessError("run the harness without -O: the InjecAgent parser relies on assert")


def scrub_environ(environ: MutableMapping[str, str]) -> int:
    """Remove every variable whose name looks like a key or token; return how many."""
    names = [name for name in environ if _SECRET_NAME.search(name)]
    for name in names:
        del environ[name]
    return len(names)


def worker_env() -> dict[str, str]:
    """The worker's whole environment: a fixed allow-list, no inherited variable."""
    return {"PYTHONHASHSEED": "0", "PATH": os.defpath}


def _git(repo: Path, *args: str) -> bytes:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if proc.returncode != 0:
        raise HarnessError(f"git {args[0]} failed in {repo.name}")
    return proc.stdout


def resolve_sha(repo: Path, rev: str) -> str:
    return _git(repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").decode().strip()


def require_full_clone(repo: Path) -> None:
    """Refuse a partial clone: git would fetch missing blobs from the network during export."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "config", "--get", "extensions.partialClone"],
        capture_output=True,
        check=False,
    )
    if proc.stdout.strip():
        raise HarnessError(f"{repo.name} is a partial clone; use a full clone")


def export_pin(repo: Path, sha: str, dest: Path) -> None:
    """Write the pinned tree into dest with git archive; the repository is only read."""
    with tarfile.open(fileobj=io.BytesIO(_git(repo, "archive", "--format=tar", sha))) as tar:
        tar.extractall(dest, filter="data")


def file_hashes(root: Path, rels: tuple[str, ...]) -> dict[str, str | None]:
    """sha256 of each file under root; None for a file the tree lacks."""
    out: dict[str, str | None] = {}
    for rel in rels:
        path = root / rel
        out[rel] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return out


def installed_sha256() -> str:
    """sha256 of the sorted ``name==version`` lines of the running environment."""
    lines = sorted(
        f"{(d.metadata['Name'] or '').lower()}=={d.version}" for d in metadata.distributions()
    )
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def harness_record(repo: Path, practice: bool) -> dict[str, Any]:
    """The harness commit, the sha256 of each harness file and of uv.lock (section 9)."""
    dirty = _git(repo, "status", "--porcelain", "--", HARNESS_DIR, "uv.lock").decode().strip()
    if dirty and not practice:
        raise HarnessError("harness files differ from the commit; commit them or use --practice")
    files = sorted(
        p.relative_to(repo).as_posix()
        for p in (repo / HARNESS_DIR).rglob("*.py")
        if "__pycache__" not in p.parts
    )
    return {
        "commit": resolve_sha(repo, "HEAD"),
        "frozen": not dirty,
        "practice": practice,
        "files_sha256": file_hashes(repo, (*files, "uv.lock")),
        "installed_sha256": installed_sha256(),
        "python": sys.version.split()[0],
    }
