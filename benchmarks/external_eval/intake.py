"""Intake checks and limits (protocol section 9).

A failure here is an intake failure: the benchmark is reported as not evaluated with the
reason (protocol section 10). Messages name paths, fields and counts, never record text.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import subprocess
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ValidationError, field_validator

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

#: The default download folder: git-ignored (a test checks it with ``git check-ignore``) and
#: apart from the harness scripts.
DOWNLOADS = "downloads/external-eval"

#: Files with a sha256 in protocol section 1, by their path in the benchmark's tree.
SECTION_1: dict[str, str] = {
    "data/judge-comparison.csv": (
        "dacaf76a1057785f11b0fc6aa07b9a73cdab588319ddfc5e8cef2909e5b112a5"
    ),
    "data/classifier_val_sets/text_behaviors_val_set.json": (
        "e740727b6874e492063e097122a9916833d57f9bd2ce3e86713ec188741a41c8"
    ),
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DRIVE = re.compile(r"^[A-Za-z]:")
_MIT = "permission is hereby granted, free of charge, to any person obtaining a copy"


class HarnessError(Exception):
    """A run that cannot go on: bad flags, paths, pins or worker output."""


class IntakeError(HarnessError):
    """A benchmark that fails intake goes to protocol section 10."""


@dataclass(frozen=True)
class ZipLimits:
    """Limits on ``results.zip``, set before any archive's size is known."""

    compressed_bytes: int = 2_000_000_000
    members: int = 20_000
    member_bytes: int = 500_000_000
    total_bytes: int = 4_000_000_000
    ratio: int = 100


class Manifest(BaseModel):
    """The sha256 manifest committed in the intake addendum before any file is parsed."""

    files: dict[str, str]
    licence: str
    terms: str | None = None

    @field_validator("files")
    @classmethod
    def _hashes(cls, files: dict[str, str]) -> dict[str, str]:
        bad = [rel for rel, digest in files.items() if not _SHA256.match(digest)]
        if bad:
            raise ValueError(f"{len(bad)} entries are not lowercase sha256 hex")
        return files


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_manifest(path: Path) -> Manifest:
    try:
        return Manifest.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise IntakeError(f"manifest {path.name} is unreadable: {type(exc).__name__}") from exc


def _safe_rel(rel: str) -> bool:
    p = PurePosixPath(rel)
    return bool(rel) and not p.is_absolute() and ".." not in p.parts and "\\" not in rel


def load(
    root: Path,
    rel: str,
    manifest: Mapping[str, str],
    expected: Mapping[str, str],
    max_bytes: int | None = None,
) -> bytes:
    """Read one listed input file and check its sha256 before anything parses it."""
    if not _safe_rel(rel) or rel not in manifest:
        raise IntakeError(f"{rel or '(empty path)'}: not a listed relative path")
    path = root / rel
    if not path.resolve().is_relative_to(root.resolve()):
        raise IntakeError(f"{rel}: resolves outside the intake folder")
    if not path.is_file():
        raise IntakeError(f"{rel}: missing")
    if max_bytes is not None and path.stat().st_size > max_bytes:
        raise IntakeError(f"{rel}: over the {max_bytes} byte compressed limit")
    data = path.read_bytes()
    digest = sha256(data)
    if digest != manifest[rel]:
        raise IntakeError(f"{rel}: sha256 {digest} differs from the manifest")
    if rel in expected and digest != expected[rel]:
        raise IntakeError(f"{rel}: sha256 {digest} differs from protocol section 1")
    return data


def _unsafe_name(name: str) -> bool:
    return ".." in name or name.startswith(("/", "\\")) or bool(_DRIVE.match(name))


def open_zip(data: bytes, limits: ZipLimits | None = None) -> zipfile.ZipFile:
    """Open an archive in memory after checking every member against the limits."""
    lim = limits or ZipLimits()
    if len(data) > lim.compressed_bytes:
        raise IntakeError(f"archive is over the {lim.compressed_bytes} byte compressed limit")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IntakeError("archive is not a readable zip") from exc
    infos = zf.infolist()
    if len(infos) > lim.members:
        raise IntakeError(f"archive has {len(infos)} members, over {lim.members}")
    total = 0
    for i, info in enumerate(infos):
        if _unsafe_name(info.filename):
            raise IntakeError(f"archive member {i}: member name is not a safe relative path")
        if stat.S_ISLNK(info.external_attr >> 16):
            raise IntakeError(f"archive member {i}: symlink")
        if info.flag_bits & 0x1:
            raise IntakeError(f"archive member {i}: encrypted")
        if info.file_size > lim.member_bytes:
            raise IntakeError(f"archive member {i}: member over {lim.member_bytes} bytes")
        if info.file_size > lim.ratio * info.compress_size:
            raise IntakeError(f"archive member {i}: compression ratio over {lim.ratio}")
        total += info.file_size
    if total > lim.total_bytes:
        raise IntakeError(f"archive holds {total} bytes uncompressed, over the total limit")
    return zf


def read_member(zf: zipfile.ZipFile, index: int, info: zipfile.ZipInfo) -> bytes:
    """A member's bytes; a damaged member fails intake. Messages name the index, never the name."""
    try:
        with zf.open(info) as f:
            data = f.read(info.file_size + 1)
    except (zipfile.BadZipFile, zlib.error, RuntimeError, NotImplementedError, EOFError) as exc:
        raise IntakeError(f"archive member {index}: unreadable ({type(exc).__name__})") from None
    if len(data) != info.file_size:
        raise IntakeError(f"archive member {index}: differs from its declared size")
    return data


def spdx_id(text: bytes) -> str:
    """SPDX id of a licence text; only MIT is recognised, anything else fails intake."""
    normalised = " ".join(text.decode("utf-8", errors="replace").lower().split())
    if _MIT in normalised:
        return "MIT"
    raise IntakeError("licence text is not recognised as allowing research use")


def require_fields(record: object, fields: Sequence[str], where: str) -> None:
    """Check presence only; label values are not tallied at this step (check 4)."""
    if not isinstance(record, dict):
        raise IntakeError(f"{where}: not an object")
    for name in fields:
        if name not in record:
            raise IntakeError(f"{where} lacks {name}")


def check_responses_not_targets(
    rows: Iterable[Mapping[str, Any]], behaviours: Iterable[Mapping[str, Any]]
) -> None:
    """Check 5: a joined row whose response equals its behaviour's Target fails intake."""
    targets = {b.get("Goal"): b.get("Target") for b in behaviours}
    for row in rows:
        goal = row.get("goal")
        if goal in targets and row.get("target_response") == targets[goal]:
            raise IntakeError("target_response holds attack targets, not model responses")


def require_outside_or_ignored(repo: Path, path: Path) -> None:
    """Refuse a data or output folder inside the repository unless git ignores its contents."""
    repo, path = repo.resolve(), path.resolve()
    if not path.is_relative_to(repo):
        return
    proc = subprocess.run(  # a child path, so a folder rule such as `downloads/` applies
        ["git", "-C", str(repo), "check-ignore", "-q", "--no-index", str(path / "any")],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise HarnessError(f"{path.relative_to(repo)} is inside the repository and not git-ignored")


def parse_json(data: bytes, where: str) -> Any:
    try:
        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeError(f"{where}: not valid JSON") from exc
