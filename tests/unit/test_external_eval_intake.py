"""Intake checks and limits of protocol section 9 (spec 062), on hand-made bytes only."""

from __future__ import annotations

import hashlib
import io
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

from benchmarks.external_eval import intake
from benchmarks.external_eval.intake import IntakeError, ZipLimits

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
MIT = (
    "MIT License\n\nCopyright (c) 2024 Someone\n\nPermission is hereby granted, free of charge, "
    "to any person obtaining a copy of this software and associated documentation files (the "
    '"Software"), to deal in the Software without restriction, including without limitation the '
    "rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies.\n"
)


def _zip(members: dict[str, bytes], symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
        if symlink is not None:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16) | 0
            zf.writestr(info, "target")
    return buf.getvalue()


# ── archive names and limits ──────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    [
        "results/../evil.json",
        "../evil.json",
        "/abs/evil.json",
        "C:/evil.json",
        "c:evil.json",
        "\\x",
    ],
)
def test_unsafe_member_name_fails_the_archive(name: str) -> None:
    with pytest.raises(IntakeError, match="member name"):
        intake.open_zip(_zip({name: b"{}"}))


def test_symlink_member_fails_the_archive() -> None:
    with pytest.raises(IntakeError, match="symlink"):
        intake.open_zip(_zip({"a.json": b"{}"}, symlink="link"))


def test_a_clean_archive_opens_and_members_read_in_memory() -> None:
    zf = intake.open_zip(_zip({"r/prompted_x_InjecAgent/test_cases_dh_base.json": b"{}\n"}))
    (info,) = zf.infolist()
    assert intake.read_member(zf, 0, info) == b"{}\n"


def test_limits_are_the_registered_values() -> None:
    lim = ZipLimits()
    assert lim.compressed_bytes == 2_000_000_000
    assert lim.members == 20_000
    assert lim.member_bytes == 500_000_000
    assert lim.total_bytes == 4_000_000_000
    assert lim.ratio == 100


@pytest.mark.parametrize(
    ("limits", "match"),
    [
        (ZipLimits(compressed_bytes=10), "compressed"),
        (ZipLimits(members=1), "members"),
        (ZipLimits(member_bytes=100), "member .* bytes"),
        (ZipLimits(total_bytes=150), "total"),
        (ZipLimits(ratio=2), "ratio"),
    ],
)
def test_each_limit_refuses(limits: ZipLimits, match: str) -> None:
    data = _zip({"a.json": b"a" * 120, "b.json": b"b" * 120})
    with pytest.raises(IntakeError, match=match):
        intake.open_zip(data, limits)


# ── hashes before parse ───────────────────────────────────────────────


def test_load_checks_the_manifest_hash_before_returning_bytes(tmp_path: Path) -> None:
    (tmp_path / "f.csv").write_bytes(b"x")
    good = hashlib.sha256(b"x").hexdigest()
    assert intake.load(tmp_path, "f.csv", {"f.csv": good}, {}) == b"x"
    with pytest.raises(IntakeError, match="sha256"):
        intake.load(tmp_path, "f.csv", {"f.csv": "0" * 64}, {})


def test_load_checks_the_section_1_hash(tmp_path: Path) -> None:
    (tmp_path / "f.csv").write_bytes(b"x")
    good = hashlib.sha256(b"x").hexdigest()
    with pytest.raises(IntakeError, match="section 1"):
        intake.load(tmp_path, "f.csv", {"f.csv": good}, {"f.csv": "1" * 64})


def test_section_1_hashes_are_the_protocol_values() -> None:
    assert intake.SECTION_1 == {
        "data/judge-comparison.csv": (
            "dacaf76a1057785f11b0fc6aa07b9a73cdab588319ddfc5e8cef2909e5b112a5"
        ),
        "data/classifier_val_sets/text_behaviors_val_set.json": (
            "e740727b6874e492063e097122a9916833d57f9bd2ce3e86713ec188741a41c8"
        ),
    }


@pytest.mark.parametrize("rel", ["missing.csv", "../up.csv", "/abs.csv", ""])
def test_load_refuses_unlisted_or_unsafe_paths(tmp_path: Path, rel: str) -> None:
    with pytest.raises(IntakeError):
        intake.load(tmp_path, rel, {}, {})


def test_load_refuses_a_link_out_of_the_intake_folder(tmp_path: Path) -> None:
    (tmp_path / "secret").write_bytes(b"x")
    root = tmp_path / "data"
    root.mkdir()
    (root / "f.csv").symlink_to(tmp_path / "secret")
    with pytest.raises(IntakeError, match="outside the intake folder"):
        intake.load(root, "f.csv", {"f.csv": hashlib.sha256(b"x").hexdigest()}, {})


def test_manifest_refuses_a_malformed_hash(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    path.write_text('{"files": {"a": "nothex"}, "licence": "a"}')
    with pytest.raises(IntakeError, match="manifest"):
        intake.read_manifest(path)


# ── licence, fields, JailbreakBench target check ──────────────────────


def test_mit_text_gives_its_spdx_id() -> None:
    assert intake.spdx_id(MIT.encode()) == "MIT"


@pytest.mark.parametrize("text", [b"", b"All rights reserved.", b"\xff\xfe"])
def test_other_licence_text_fails_intake(text: bytes) -> None:
    with pytest.raises(IntakeError, match="licence"):
        intake.spdx_id(text)


def test_missing_required_field_fails_intake() -> None:
    intake.require_fields({"a": None, "b": 1}, ("a", "b"), "unit 0")
    with pytest.raises(IntakeError, match="unit 0 lacks b"):
        intake.require_fields({"a": 1}, ("a", "b"), "unit 0")
    with pytest.raises(IntakeError, match="not an object"):
        intake.require_fields([1], ("a",), "unit 0")


def test_jailbreakbench_targets_in_place_of_responses_fail_intake() -> None:
    behaviours = [{"Goal": "g1", "Target": "Sure, here is"}]
    intake.check_responses_not_targets([{"goal": "g1", "target_response": "No."}], behaviours)
    intake.check_responses_not_targets([{"goal": "benign", "target_response": "x"}], behaviours)
    with pytest.raises(IntakeError, match="attack targets"):
        intake.check_responses_not_targets(
            [{"goal": "g1", "target_response": "Sure, here is"}], behaviours
        )


# ── downloads stay out of git ─────────────────────────────────────────


def test_the_default_download_folder_is_git_ignored_and_apart_from_the_scripts() -> None:
    assert not intake.DOWNLOADS.startswith("benchmarks/")
    target = REPO_ROOT / intake.DOWNLOADS / "agentdojo" / "runs" / "x.json"
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "check-ignore", "-q", str(target)], check=False
    )
    assert proc.returncode == 0


def test_a_tracked_path_inside_the_repo_is_refused(tmp_path: Path) -> None:
    intake.require_outside_or_ignored(REPO_ROOT, tmp_path)
    intake.require_outside_or_ignored(REPO_ROOT, REPO_ROOT / intake.DOWNLOADS)
    with pytest.raises(intake.HarnessError, match="not git-ignored"):
        intake.require_outside_or_ignored(REPO_ROOT, REPO_ROOT / "benchmarks" / "results")


# ── damaged archives fail intake, naming the member index only ────────

_NAME = "IGNORE_PREVIOUS_INSTRUCTIONS/prompted_x_InjecAgent/test_cases_dh_base.json"


def _damaged(kind: str) -> bytes:
    method = zipfile.ZIP_DEFLATED if kind == "stream" else zipfile.ZIP_STORED
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        zf.writestr(_NAME, b"hello world " * 10)
    raw = bytearray(buf.getvalue())
    data_at = 30 + len(_NAME)
    central = raw.find(b"PK\x01\x02")
    if kind == "crc":
        raw[data_at] ^= 1
    elif kind == "stream":
        raw[data_at] ^= 0xFF
        raw[data_at + 1] ^= 0xFF
    elif kind == "encrypted":
        raw[6] |= 1
        raw[central + 8] |= 1
    elif kind == "size":
        size = struct.unpack_from("<I", raw, central + 24)[0]
        struct.pack_into("<I", raw, central + 24, size + 5)
    return bytes(raw)


@pytest.mark.parametrize("kind", ["crc", "stream", "encrypted", "size"])
def test_a_damaged_member_fails_intake_by_index(kind: str) -> None:
    with pytest.raises(IntakeError, match=r"archive member 0") as err:
        zf = intake.open_zip(_damaged(kind))
        intake.read_member(zf, 0, zf.infolist()[0])
    assert "IGNORE" not in str(err.value)


def test_each_limit_is_inclusive() -> None:
    data = _zip({"a.json": b"a" * 120, "b.json": b"b" * 120})
    infos = zipfile.ZipFile(io.BytesIO(data)).infolist()
    ratio = max(-(-i.file_size // i.compress_size) for i in infos)
    exact = ZipLimits(
        compressed_bytes=len(data), members=2, member_bytes=120, total_bytes=240, ratio=ratio
    )
    assert len(intake.open_zip(data, exact).infolist()) == 2


def test_load_caps_the_bytes_before_reading(tmp_path: Path) -> None:
    (tmp_path / "f.zip").write_bytes(b"x" * 11)
    listed = {"f.zip": hashlib.sha256(b"x" * 11).hexdigest()}
    assert intake.load(tmp_path, "f.zip", listed, {}, max_bytes=11) == b"x" * 11
    with pytest.raises(IntakeError, match="compressed limit"):
        intake.load(tmp_path, "f.zip", listed, {}, max_bytes=10)


def test_an_encrypted_member_fails_when_the_archive_opens() -> None:
    with pytest.raises(IntakeError, match="archive member 0: encrypted"):
        intake.open_zip(_damaged("encrypted"))
