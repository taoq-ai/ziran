"""Intake plus mapping: one benchmark's listed files to units and intake counts."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from benchmarks.external_eval import intake, mapping
from benchmarks.external_eval.injecagent_eval import SOURCE_SHA256
from benchmarks.external_eval.intake import IntakeError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

#: Each benchmark's primary predictor (protocol section 6).
PRIMARY = {
    "agentdojo": "pipeline",
    "injecagent": "refusal",
    "jailbreakbench": "refusal",
    "harmbench": "refusal",
}
JBB_RESPONSES = "data/judge-comparison.csv"
JBB_BEHAVIOURS = "data/harmful-behaviors.csv"
HARMBENCH_SET = "data/classifier_val_sets/text_behaviors_val_set.json"
INJECAGENT_ZIP = "results.zip"


class Collected(BaseModel):
    units: list[mapping.Unit]
    counts: dict[str, int]
    spdx: str
    terms_spdx: str | None
    manifest_files: int
    extra_hashes: dict[str, str]


def _decode(data: bytes, where: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntakeError(f"{where}: not UTF-8") from exc


def _agentdojo(load: Callable[[str], bytes], files: list[str]) -> tuple[list[mapping.Unit], int]:
    units: list[mapping.Unit] = []
    outside = 0
    for rel in files:
        if not mapping.agentdojo_admitted(rel):
            outside += 1
            continue
        units += mapping.agentdojo_units(rel, intake.parse_json(load(rel), rel))
    return units, outside


def _injecagent_items(text: str, where: str) -> list[tuple[int, Any]]:
    try:
        whole = json.loads(text)
    except json.JSONDecodeError:
        whole = None
    if isinstance(whole, list):
        return list(enumerate(whole))
    lines = text.splitlines()
    return [
        (i, intake.parse_json(ln.encode(), f"{where}:{i}"))
        for i, ln in enumerate(lines)
        if ln.strip()
    ]


def _injecagent(load: Callable[[str], bytes], _files: list[str]) -> tuple[list[mapping.Unit], int]:
    zf = intake.open_zip(load(INJECAGENT_ZIP))
    units: list[mapping.Unit] = []
    outside = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        if mapping.injecagent_member(info.filename) is None:
            outside += 1
            continue
        text = _decode(intake.read_member(zf, info), info.filename)
        for i, item in _injecagent_items(text, info.filename):
            units += mapping.injecagent_units(info.filename, i, item)
    return units, outside


def _csv_rows(data: bytes, where: str) -> list[dict[str, Any]]:
    return list(csv.DictReader(io.StringIO(_decode(data, where), newline="")))


def _jailbreakbench(
    load: Callable[[str], bytes], _files: list[str]
) -> tuple[list[mapping.Unit], int]:
    rows = _csv_rows(load(JBB_RESPONSES), JBB_RESPONSES)
    behaviours = _csv_rows(load(JBB_BEHAVIOURS), JBB_BEHAVIOURS)
    for i, row in enumerate(rows):
        intake.require_fields(row, mapping.JAILBREAKBENCH_FIELDS, f"row {i}")
        if any(row[f] is None for f in mapping.JAILBREAKBENCH_FIELDS):
            raise IntakeError(f"row {i}: short row")
    for i, b in enumerate(behaviours):
        intake.require_fields(b, ("Goal", "Target"), f"behaviour {i}")
    intake.check_responses_not_targets(rows, behaviours)
    return [mapping.jailbreakbench_unit(i, r) for i, r in enumerate(rows)], 0


def _harmbench(load: Callable[[str], bytes], _files: list[str]) -> tuple[list[mapping.Unit], int]:
    return mapping.harmbench_units(intake.parse_json(load(HARMBENCH_SET), HARMBENCH_SET)), 0


_BUILDERS = {
    "agentdojo": _agentdojo,
    "injecagent": _injecagent,
    "jailbreakbench": _jailbreakbench,
    "harmbench": _harmbench,
}


def _tally(units: list[mapping.Unit], outside: int) -> dict[str, int]:
    counts: Counter[str] = Counter(split=0, outside_split=outside)
    for u in units:
        if u.variant == "post_injection":
            counts["no_marker"] += "no_marker" in u.notes
            continue
        if u.variant != "whole":
            continue
        counts["split"] += 1
        if u.excluded:
            counts[f"excluded:{u.excluded}"] += 1
        for note in u.notes:
            counts[
                "shipped_eval_differs"
                if note == "shipped_eval_differs"
                else f"invalid_reason:{note}"
            ] += 1
    return dict(counts)


def collect(
    benchmark: str,
    root: Path,
    manifest: intake.Manifest,
    expected: Mapping[str, str] = intake.SECTION_1,
) -> Collected:
    """Hash every listed file, check licences, then parse and map the split."""
    if benchmark not in _BUILDERS:
        raise IntakeError(f"unknown benchmark {benchmark}")
    limit = intake.ZipLimits().compressed_bytes

    def load(rel: str) -> bytes:
        cap = limit if benchmark == "injecagent" and rel == INJECAGENT_ZIP else None
        return intake.load(root, rel, manifest.files, expected, cap)

    for rel in manifest.files:  # check 1: every hash before any file is parsed
        load(rel)
    spdx = intake.spdx_id(load(manifest.licence))
    terms = None
    if benchmark == "injecagent":
        if manifest.terms is None:
            raise IntakeError("results.zip states no licence and the manifest names no terms")
        terms = intake.spdx_id(load(manifest.terms))
    skip = {manifest.licence, manifest.terms}
    data_files = sorted(rel for rel in manifest.files if rel not in skip)
    units, outside = _BUILDERS[benchmark](load, data_files)
    return Collected(
        units=units,
        counts=_tally(units, outside),
        spdx=spdx,
        terms_spdx=terms,
        manifest_files=len(manifest.files),
        extra_hashes={"injecagent_output_parsing_py": SOURCE_SHA256}
        if benchmark == "injecagent"
        else {},
    )
