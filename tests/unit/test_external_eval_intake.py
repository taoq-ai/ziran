"""Intake checks and limits of protocol section 9 (spec 062), on hand-made bytes only."""

from __future__ import annotations

import contextlib
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


@pytest.mark.parametrize("method", ["ZIP_BZIP2", "ZIP_LZMA", "ZIP_ZSTANDARD"])
def test_only_stored_and_deflate_members_are_read(method: str) -> None:
    if not hasattr(zipfile, method):
        pytest.skip(f"zipfile has no {method} on this Python")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", getattr(zipfile, method)) as zf:
        zf.writestr(_NAME, b"hello world " * 10)
    with pytest.raises(IntakeError, match="archive member 0: compression method") as err:
        intake.open_zip(buf.getvalue())
    assert "IGNORE" not in str(err.value)


# ── round 3: damaged headers fail intake, never a traceback ───────────

_MEMBER = "prompted_x_InjecAgent/test_cases_dh_base.json"


def damaged_header(kind: str) -> bytes:
    """A one-member archive with one header field broken in the named way."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(_MEMBER, b"{}\n")
    raw = bytearray(buf.getvalue())
    central = raw.find(b"PK\x01\x02")
    end = raw.find(b"PK\x05\x06")
    if kind == "cd_offset":  # central directory offset one byte too large
        offset = struct.unpack_from("<I", raw, end + 16)[0]
        struct.pack_into("<I", raw, end + 16, offset + 1)
    elif kind == "local_name":  # UTF-8 flag and invalid name bytes in the local header
        raw[7] |= 0x08
        raw[30 : 30 + len(_MEMBER)] = b"\xff" * len(_MEMBER)
    elif kind == "version":  # extract version 25.5
        raw[central + 6] = 0xFF
    elif kind == "cd_name":  # UTF-8 flag and invalid name bytes in the central directory
        raw[central + 9] |= 0x08
        raw[central + 46] = 0xFF
    return bytes(raw)


@pytest.mark.parametrize("kind", ["cd_offset", "local_name", "version", "cd_name"])
def test_a_damaged_header_fails_intake(kind: str) -> None:
    with pytest.raises(IntakeError):
        zf = intake.open_zip(damaged_header(kind))
        for i, info in enumerate(zf.infolist()):
            intake.read_member(zf, i, info)


def test_byte_mutation_fuzz_lets_only_intake_errors_out() -> None:
    import random

    from benchmarks.external_eval import collect as collector

    seeds = []
    for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        for zip64 in (False, True):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", method, allowZip64=True) as zf:
                zf.writestr("pad.txt", b"hello" * 20)
                with zf.open(_MEMBER, "w", force_zip64=zip64) as f:
                    f.write(b'{"a": 1}\n' * 3)
            seeds.append(buf.getvalue())
    rng = random.Random(20261029)
    for _ in range(3000):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 4)):
            at = rng.randrange(len(data))
            for j in range(rng.choice((1, 2, 4))):
                if at + j < len(data):
                    data[at + j] = rng.choice((0, 0xFF, rng.randrange(256)))
        try:
            zf = intake.open_zip(bytes(data))
            for i, info in enumerate(zf.infolist()):
                if info.is_dir() or collector.mapping.injecagent_member(info.filename) is None:
                    continue
                where = f"archive member {i}"
                collector._injecagent_items(
                    collector._decode(intake.read_member(zf, i, info), where), where
                )
        except IntakeError:
            pass


# ── round 4: zip64 fields, hostile JSON and CSV payloads ──────────────


def _cd_zip64(offset: int | None = None, sizes: tuple[int, int] | None = None) -> bytes:
    """One stored member whose central entry moves the offset or sizes into a zip64 extra."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("pad.txt", b"x" * 50)
        zf.writestr(_MEMBER, b'{"a": 1}\n')
    raw = bytearray(buf.getvalue())
    central = raw.rfind(b"PK\x01\x02")
    nlen, xlen = struct.unpack_from("<HH", raw, central + 28)
    entry = bytearray(raw[central : central + 46 + nlen])
    values: list[int] = []
    if sizes is not None:
        struct.pack_into("<II", entry, 20, 0xFFFFFFFF, 0xFFFFFFFF)
        values += [sizes[1], sizes[0]]  # zipfile reads file size, then compressed size
    if offset is not None:
        struct.pack_into("<I", entry, 42, 0xFFFFFFFF)
        values.append(offset)
    extra = struct.pack("<HH", 1, 8 * len(values)) + b"".join(struct.pack("<Q", v) for v in values)
    struct.pack_into("<H", entry, 30, len(extra))
    old = 46 + nlen + xlen
    out = raw[:central] + entry + extra + raw[central + old :]
    end = out.rfind(b"PK\x05\x06")
    size = struct.unpack_from("<I", out, end + 12)[0]
    struct.pack_into("<I", out, end + 12, size - old + len(entry) + len(extra))
    return bytes(out)


def _read_all(data: bytes) -> None:
    zf = intake.open_zip(data)
    for i, info in enumerate(zf.infolist()):
        intake.read_member(zf, i, info)


BOUNDARIES = (0, 2**31, 2**32 - 1, 2**33, 2**63 - 1, 2**63, 2**64 - 1)


@pytest.mark.parametrize("value", BOUNDARIES)
def test_a_zip64_offset_at_a_boundary_fails_intake_or_reads(value: int) -> None:
    with contextlib.suppress(IntakeError):
        _read_all(_cd_zip64(offset=value))


def test_a_zip64_offset_past_ssize_t_fails_intake() -> None:
    with pytest.raises(IntakeError, match="archive member 1"):
        _read_all(_cd_zip64(offset=2**63))


@pytest.mark.parametrize("sizes", [(v, w) for v in BOUNDARIES for w in (0, 9, 2**63, 2**64 - 1)])
def test_zip64_sizes_at_boundaries_fail_intake_or_read(sizes: tuple[int, int]) -> None:
    with contextlib.suppress(IntakeError):
        _read_all(_cd_zip64(sizes=sizes))


@pytest.mark.parametrize(
    "payload",
    [b"1" * 5000, b"[" * 200_000 + b"]" * 200_000, b'{"a":' * 200_000 + b"1" + b"}" * 200_000],
    ids=["huge_int", "deep_list", "deep_object"],
)
def test_hostile_json_fails_intake(payload: bytes) -> None:
    from benchmarks.external_eval import collect as collector

    with pytest.raises(IntakeError, match="not valid JSON"):
        intake.parse_json(payload, "unit 0")
    with pytest.raises(IntakeError, match="not valid JSON"):
        collector._injecagent_items(payload.decode(), "archive member 0")


def test_csv_fields_are_read_up_to_the_stated_bound() -> None:
    from benchmarks.external_eval import collect as collector

    assert collector.CSV_FIELD_CHARS == 10_000_000
    long_ok = b"a\n" + b"x" * 200_000 + b"\n"
    assert len(collector._csv_rows(long_ok, "f.csv")[0]["a"]) == 200_000
    too_long = b"a\n" + b"x" * (collector.CSV_FIELD_CHARS + 1) + b"\n"
    with pytest.raises(IntakeError, match=r"f\.csv: not readable CSV"):
        collector._csv_rows(too_long, "f.csv")


def test_fuzz_zip64_fields_and_member_payloads_let_only_intake_errors_out() -> None:
    import json as jsonlib
    import random

    from benchmarks.external_eval import collect as collector
    from benchmarks.external_eval import mapping
    from tests.unit.test_external_eval_mapping import SUCC_OUTPUT, injec_item

    rng = random.Random(20261030)
    edges = [*BOUNDARIES, 1, 9, 2**16, rng.randrange(2**64)]
    for _ in range(300):  # zip64 header fields at boundary values
        offset = rng.choice([None, *edges])
        sizes = rng.choice([None, (rng.choice(edges), rng.choice(edges))])
        if offset is None and sizes is None:
            continue
        with contextlib.suppress(IntakeError):
            _read_all(_cd_zip64(offset=offset, sizes=sizes))
    good = (jsonlib.dumps(injec_item(SUCC_OUTPUT)) + "\n").encode() * 2
    for _ in range(1500):  # mutated payloads inside a valid archive
        body = bytearray(good)
        for _ in range(rng.randint(1, 6)):
            at = rng.randrange(len(body))
            body[at : at + rng.choice((0, 1, 3))] = b"".join(
                rng.choice((b"[", b"{", b"}", b'"', b"\\", b"9", b"\xff", b"\n", b"\x00"))
                for _ in range(rng.choice((1, 2, 50)))
            )
        buf = io.BytesIO()
        with zipfile.ZipFile(
            buf, "w", rng.choice((zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
        ) as zf:
            zf.writestr(_MEMBER, bytes(body))
        try:
            zf2 = intake.open_zip(buf.getvalue())
            (info,) = zf2.infolist()
            text = collector._decode(intake.read_member(zf2, 0, info), "archive member 0")
            for i, item in collector._injecagent_items(text, "archive member 0"):
                mapping.injecagent_units(info.filename, i, item, f"archive member 0 line {i}")
        except IntakeError:
            pass


def test_a_patched_warnings_warn_cannot_crash_a_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """crewai replaces warnings.warn with one lacking skip_file_prefixes, which zipfile uses."""
    import warnings

    def narrow_warn(message: object, category: object = None, stacklevel: int = 1) -> None:
        return None

    monkeypatch.setattr(warnings, "warn", narrow_warn)
    with pytest.raises(IntakeError, match=r"archive member \d: unreadable \(TypeError\)"):
        _read_all(_cd_zip64(offset=0))  # overlapping entries make zipfile warn
