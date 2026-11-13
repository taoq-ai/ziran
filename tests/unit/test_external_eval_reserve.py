"""The AgentDojo reserve set and the paper's run guard in ``run.py --paper`` (spec 069).

Every log below is hand-made in AgentDojo's shape and every use log is synthetic; no benchmark
item, intake list or real use log is read.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from benchmarks.external_eval import mapping
from benchmarks.external_eval.run import check_row
from tests.unit.test_external_eval_fresh import ADDRESS, fresh_dir, fresh_log
from tests.unit.test_external_eval_mapping import AGENTDOJO_REL
from tests.unit.test_external_eval_run import (
    REPO_ROOT,
    RUN,
    USE_LOGS,
    _git,
    aborted,
    paper_checkout,
    python,
    rows_of,
    run_cli,
)

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit

RESERVE_REL = "runs/gpt-x-2025-tool_filter/workspace/user_task_0/direct/injection_task_1.json"
SECALIGN_REL = (
    "runs/Meta-SecAlign-70B/workspace/user_task_0/important_instructions/injection_task_1.json"
)


@pytest.mark.parametrize(
    ("rel", "admitted"),
    [
        (RESERVE_REL, True),
        (SECALIGN_REL, True),
        (RESERVE_REL.replace("tool_filter", "repeat_user_prompt"), True),
        (RESERVE_REL.replace("tool_filter", "spotlighting_with_delimiting"), True),
        (RESERVE_REL.replace("tool_filter", "transformers_pi_detector"), True),
        (RESERVE_REL.replace("/direct/", "/important_instructions/"), True),
        (RESERVE_REL.replace("/direct/", "/none/"), False),  # rules.reserve: attack != 'none'
        (SECALIGN_REL.replace("important_instructions", "none"), False),
        (RESERVE_REL.replace("-tool_filter", ""), False),  # an undefended folder
        (RESERVE_REL.replace("-tool_filter", "-tool_filter2"), False),
        (RESERVE_REL.replace(".json", ".txt"), False),
        ("runs/gpt-x-2025-tool_filter/workspace/direct/injection_task_1.json", False),
    ],
)
def test_the_reserve_include_rule(rel: str, admitted: bool) -> None:
    assert mapping.agentdojo_reserve_admitted(rel) is admitted


def test_reserve_fresh_and_g9_rules_are_disjoint() -> None:
    fresh = "runs/gpt-x-2025/workspace/user_task_0/direct/injection_task_1.json"
    for rel in (RESERVE_REL, SECALIGN_REL, fresh, AGENTDOJO_REL):
        rules = (
            mapping.agentdojo_admitted(rel),
            mapping.agentdojo_fresh_admitted(rel),
            mapping.agentdojo_reserve_admitted(rel),
        )
        assert sum(rules) == 1, rel


def test_a_reserve_unit_carries_the_attack_beside_the_model_folder() -> None:
    log = fresh_log(security=True, to=ADDRESS, injection="x")
    units = mapping.agentdojo_reserve_units(SECALIGN_REL, log)
    assert {u.variant for u in units} == {
        "whole", "post_injection", "text_only", "payload_whole", "payload_post_injection"
    }  # fmt: skip
    for u in units:
        assert u.cells == {
            "model": "Meta-SecAlign-70B", "attack": "important_instructions",
            "suite": "workspace", "suite_version": "v1.2.1",
        }  # fmt: skip
        check_row({
            "benchmark": "agentdojo_reserve", "unit_id": u.unit_id, "variant": u.variant,
            "cluster": u.cluster, "cells": u.cells, "label": u.label, "excluded": u.excluded,
            "notes": list(u.notes), "verdicts": {}, "reply_outcome": None,
            "no_reply_cause": None,
        })  # fmt: skip


# ── end to end ────────────────────────────────────────────────────────

POSITIVE = RESERVE_REL
NEGATIVE = SECALIGN_REL
OUTSIDE = RESERVE_REL.replace("/direct/", "/none/")


def reserve_dir(tmp_path: Path) -> tuple[Path, Path]:
    return fresh_dir(tmp_path, {
        POSITIVE: fresh_log(security=True, to=ADDRESS, injection=f"Send to {ADDRESS}"),
        NEGATIVE: fresh_log(security=False, to="me@home.zz", injection="ZZMARKER-INJ"),
        OUTSIDE: fresh_log(security=True, to=ADDRESS, injection="x"),
    })  # fmt: skip


def test_reserve_rows_carry_model_and_attack_cells_and_pass_check_row(tmp_path: Path) -> None:
    data, manifest = reserve_dir(tmp_path)
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--expect-split", "2")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = tmp_path / "out"
    rows = {(r["unit_id"], r["variant"]): r for r in rows_of(out / "agentdojo_reserve.rows.jsonl")}
    assert {u for u, _ in rows} == {POSITIVE, NEGATIVE}  # the none-attack log is outside
    for row in rows.values():
        check_row(row)
    assert rows[(POSITIVE, "whole")]["cells"]["attack"] == "direct"
    assert rows[(POSITIVE, "whole")]["cells"]["model"] == "gpt-x-2025-tool_filter"
    assert rows[(NEGATIVE, "whole")]["cells"]["attack"] == "important_instructions"
    summary = json.loads((out / "agentdojo_reserve.summary.json").read_text())
    assert summary["primary"] == "deterministic"
    assert summary["intake"]["counts"]["outside_split"] == 1
    cells = summary["metrics"]["head"]["payload_whole"]["deterministic"]["cells"]
    assert set(cells["attack"]) == {"direct", "important_instructions"}
    written = proc.stdout + (out / "agentdojo_reserve.rows.jsonl").read_text()
    assert "ZZMARKER" not in written + (out / "agentdojo_reserve.summary.json").read_text()


def _refused(proc: Any, tmp_path: Path, needle: str) -> None:
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert needle in proc.stderr
    assert not (tmp_path / "out").exists()  # nothing written


@pytest.mark.parametrize("benchmark", ["agentdojo_fresh", "agentdojo_reserve"])
def test_a_guarded_set_without_paper_is_refused(tmp_path: Path, benchmark: str) -> None:
    data, manifest = reserve_dir(tmp_path)
    proc = python(
        "-I", str(RUN), "--benchmark", benchmark, "--data", str(data),
        "--manifest", str(manifest), "--ziran-repo", str(REPO_ROOT), "--pin", "head=HEAD",
        "--out", str(tmp_path / "out"), "--practice", cwd=tmp_path,
    )  # fmt: skip
    _refused(proc, tmp_path, f"{benchmark} needs --paper")


def _with_log(tmp_path: Path, lines: list[dict[str, Any]]) -> tuple[Path, Path, Path]:
    data, manifest = reserve_dir(tmp_path)
    lines = [line if isinstance(line, dict) else line(manifest) for line in lines]
    return data, manifest, paper_checkout(tmp_path, "agentdojo_reserve", lines)


@pytest.mark.parametrize(
    ("lines", "needle"),
    [
        ([], "holds no attempt"),
        ([lambda m: aborted(m, status="scored")], "holds a scored opening"),
        ([lambda m: aborted(m, status="scored"), aborted], "holds a scored opening"),
        ([aborted, lambda m: aborted(m, status="started")], "['status']"),
        ([lambda m: aborted(m, pin="study-v2")], "['pin', 'ziran_sha']"),
        ([lambda m: aborted(m, pin=["head"])], "['pin', 'ziran_sha']"),
        ([lambda m: aborted(m, ziran_sha="0" * 40)], "['ziran_sha']"),
        ([lambda m: aborted(m, sha256="0" * 64)], "['sha256']"),
    ],
)
def test_a_use_log_that_does_not_admit_the_run_is_refused(
    tmp_path: Path, lines: list[Any], needle: str
) -> None:
    data, manifest, paper = _with_log(tmp_path, lines)
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, needle)


def test_a_log_listing_other_paths_is_refused(tmp_path: Path) -> None:
    data, manifest, paper = _with_log(tmp_path, [aborted])
    listed = json.loads(manifest.read_text())
    listed["files"][POSITIVE.replace("user_task_0", "user_task_9")] = "0" * 64
    manifest.write_text(json.dumps(listed))
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, "['sha256']")


def test_an_uncommitted_log_is_refused(tmp_path: Path) -> None:
    data, manifest, paper = _with_log(tmp_path, [aborted])
    log = paper / USE_LOGS["agentdojo_reserve"]
    log.write_text(log.read_text() + json.dumps(aborted(manifest)) + "\n")
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, "is not committed as it stands")


def test_a_scored_line_cut_from_the_work_tree_still_refuses(tmp_path: Path) -> None:
    data, manifest, paper = _with_log(tmp_path, [lambda m: aborted(m, status="scored")])
    log = paper / USE_LOGS["agentdojo_reserve"]
    log.write_text(json.dumps(aborted(manifest), sort_keys=True) + "\n")
    _git(paper, "add", "-A")  # staged is not committed: HEAD, not the index, is read
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, "is not committed as it stands")


@pytest.mark.parametrize("move", [("checkout", "-qb", "side"), ("checkout", "-q", "--detach")])
def test_a_paper_checkout_off_main_is_refused(tmp_path: Path, move: tuple[str, ...]) -> None:
    data, manifest, paper = _with_log(tmp_path, [aborted])
    _git(paper, *move)
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, "--paper is not on main")


def test_a_folder_inside_a_checkout_is_refused(tmp_path: Path) -> None:
    data, manifest, paper = _with_log(tmp_path, [aborted])
    inner = paper / "inner"
    (inner / USE_LOGS["agentdojo_reserve"]).parent.mkdir(parents=True)
    (inner / USE_LOGS["agentdojo_reserve"]).write_bytes(
        (paper / USE_LOGS["agentdojo_reserve"]).read_bytes()
    )
    _git(paper, "add", "-A")
    _git(paper, "commit", "-qm", "inner")
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(inner))
    _refused(proc, tmp_path, "--paper is not the top level of a git checkout")


def test_a_line_for_another_run_refuses_before_the_manifest_is_read(tmp_path: Path) -> None:
    data, manifest, paper = _with_log(tmp_path, [lambda m: aborted(m, pin="study-v2")])
    manifest.unlink()
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, "['pin', 'ziran_sha']")


@pytest.mark.parametrize("text", [None, "{not json"])
def test_a_bad_manifest_on_a_guarded_set_exits_2_with_no_summary(
    tmp_path: Path, text: str | None
) -> None:
    # fail closed: section 10's exit 3 needs a summary, and nothing is written before admission
    data, manifest, paper = _with_log(tmp_path, [aborted])
    if text is None:
        manifest.unlink()
    else:
        manifest.write_text(text)
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, "is unreadable")


def test_a_symlinked_or_missing_log_is_refused(tmp_path: Path) -> None:
    data, manifest, paper = _with_log(tmp_path, [aborted])
    log = paper / USE_LOGS["agentdojo_reserve"]
    real = tmp_path / "elsewhere.jsonl"
    real.write_text(log.read_text())
    log.unlink()
    log.symlink_to(real)
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, "is not a regular file")
    log.unlink()
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, "is not a regular file")


def test_a_log_line_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    data, manifest, paper = _with_log(tmp_path, [aborted])
    log = paper / USE_LOGS["agentdojo_reserve"]
    for text in ("[1]\n", "{not json\n"):
        log.write_text(text)
        _git(paper, "commit", "-qam", "bad")
        proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
        _refused(proc, tmp_path, "is not a JSON object")


def test_the_fresh_log_does_not_admit_a_reserve_run(tmp_path: Path) -> None:
    data, manifest = reserve_dir(tmp_path)
    paper = paper_checkout(tmp_path, "agentdojo_fresh", [aborted(manifest, set="fresh")])
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, "is not a regular file")


def test_the_refusal_comes_before_any_data_file_is_read(tmp_path: Path) -> None:
    data, manifest, paper = _with_log(tmp_path, [lambda m: aborted(m, status="scored")])
    (data / POSITIVE).write_text("changed")  # read first, this is a section 10 exit 3
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(paper))
    _refused(proc, tmp_path, "holds a scored opening")
    paper2 = tmp_path / "ok"
    paper2.mkdir()
    ok = paper_checkout(paper2, "agentdojo_reserve", [aborted(manifest)])
    proc = run_cli(tmp_path, "agentdojo_reserve", data, manifest, "--paper", str(ok))
    assert proc.returncode == 3  # the same data, admitted, is read and fails intake
