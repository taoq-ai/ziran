"""Run isolation and the CLI end to end on hand-made fixtures (spec 062, protocol sections 4, 9).

The end-to-end tests export the current commit with ``git archive`` as the pin and score
hand-made AgentDojo and InjecAgent fixtures; no benchmark item is involved.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from benchmarks.external_eval import isolation
from benchmarks.external_eval.intake import HarnessError
from benchmarks.external_eval.run import _pins
from tests.unit.test_external_eval_mapping import (
    AGENTDOJO_REL,
    MEMBER,
    MIT,
    SUCC_OUTPUT,
    agentdojo_log,
    injec_item,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "benchmarks" / "external_eval"
RUN = PACKAGE / "run.py"
WORKER = PACKAGE / "worker.py"
TEXT_MARKERS = ("Summarise my files", "Sending now", "Reading it", "x@y.z", "INFORMATION")


def python(
    *args: str, cwd: Path | None = None, stdin: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        input=stdin,
        cwd=cwd,
        env=isolation.worker_env(),
        check=False,
        timeout=300,
    )


# ── interpreter flags, sockets, environment ───────────────────────────


def test_run_refuses_without_isolated_mode(tmp_path: Path) -> None:
    proc = python(str(RUN), "--help", cwd=tmp_path)
    assert proc.returncode == 2
    assert "python -I" in proc.stderr


def test_run_refuses_optimised_mode(tmp_path: Path) -> None:
    proc = python("-I", "-O", str(RUN), "--help", cwd=tmp_path)
    assert proc.returncode == 2
    assert "-O" in proc.stderr


def test_sockets_are_blocked_after_the_hook(tmp_path: Path) -> None:
    code = (
        f"import sys; sys.path.insert(0, {str(PACKAGE)!r}); import worker; worker.block_sockets()\n"
        "import socket\n"
        "try:\n    socket.socket().connect(('127.0.0.1', 9))\n"
        "except RuntimeError as exc:\n    print('blocked', exc)\n"
        "try:\n    socket.getaddrinfo('example.com', 443)\n"
        "except RuntimeError:\n    print('blocked dns')\n"
    )
    proc = python("-I", "-c", code, cwd=tmp_path)
    assert proc.stdout.splitlines() == ["blocked socket.connect is blocked", "blocked dns"]


def test_secret_like_variables_are_removed_and_only_counted() -> None:
    env = {"OPENAI_API_KEY": "k", "GH_TOKEN": "t", "AWS_SECRET_ACCESS_KEY": "s", "HOME": "/h"}
    assert isolation.scrub_environ(env) == 3
    assert env == {"HOME": "/h"}


def test_worker_environment_is_an_allow_list() -> None:
    assert isolation.worker_env() == {"PYTHONHASHSEED": "0", "PATH": isolation.os.defpath}


def test_worker_refuses_a_ziran_that_loads_outside_the_export(tmp_path: Path) -> None:
    empty = tmp_path / "export"
    empty.mkdir()
    proc = python("-I", str(WORKER), str(empty), cwd=tmp_path)
    assert proc.returncode != 0
    assert "outside the export" in proc.stderr


# ── end to end ────────────────────────────────────────────────────────


def fixture_dir(root: Path, files: dict[str, bytes], **extra: str) -> Path:
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    manifest = {"files": {r: hashlib.sha256(d).hexdigest() for r, d in files.items()}, **extra}
    path = root.parent / f"{root.name}.manifest.json"
    path.write_text(json.dumps(manifest))
    return path


def run_cli(
    tmp_path: Path, benchmark: str, data: Path, manifest: Path
) -> subprocess.CompletedProcess[str]:
    return python(
        "-I",
        str(RUN),
        "--benchmark", benchmark,
        "--data", str(data),
        "--manifest", str(manifest),
        "--ziran-repo", str(REPO_ROOT),
        "--pin", "head=HEAD",
        "--pin", "again=HEAD",
        "--out", str(tmp_path / "out"),
        "--practice",
        cwd=tmp_path,
    )  # fmt: skip


def rows_of(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_agentdojo_fixture_end_to_end(tmp_path: Path) -> None:
    data = tmp_path / "agentdojo"
    no_marker = agentdojo_log()
    no_marker["messages"][5]["content"] = "file: plain"
    files = {
        "LICENSE": MIT.encode(),
        AGENTDOJO_REL: json.dumps(agentdojo_log()).encode(),
        AGENTDOJO_REL.replace("task_1", "task_2"): json.dumps(no_marker).encode(),
    }
    proc = run_cli(tmp_path, "agentdojo", data, fixture_dir(data, files, licence="LICENSE"))
    assert proc.returncode == 0, proc.stdout
    out = tmp_path / "out"
    rows = rows_of(out / "agentdojo.rows.jsonl")
    assert len(rows) == 12
    for row in rows:
        assert set(row) == {
            "benchmark", "pin", "unit_id", "variant", "label", "excluded", "cells",
            "refusal", "side_effect", "pipeline",
        }  # fmt: skip
        assert row["label"] is True
        assert all(isinstance(row[k], bool) for k in ("refusal", "side_effect", "pipeline"))
    variants = {(r["unit_id"], r["variant"]): r for r in rows}
    assert variants[(AGENTDOJO_REL, "text_only")]["pipeline"] is False
    assert variants[(AGENTDOJO_REL, "post_injection")]["side_effect"] is True

    summary = json.loads((out / "agentdojo.summary.json").read_text())
    assert summary["status"] == "evaluated"
    assert summary["intake"]["counts"]["no_marker"] == 1
    assert summary["intake"]["spdx"] == "MIT"
    pin = summary["pins"]["head"]
    assert set(pin["files_sha256"]) >= {"ziran/application/detectors/pipeline.py", "uv.lock"}
    assert pin["defaults"]["thresholds"]["hit"] == 0.7
    assert pin["defaults"]["config"]["refusal_matchtype"] == "str"
    assert pin["modules_checked"] > 0
    whole = summary["metrics"]["head"]["whole"]["pipeline"]["all"]
    assert whole["X4"] == {"k": 2, "n": 2, "estimate": 1.0, "low": whole["X4"]["low"],
                           "high": 1.0, "undefined": False}  # fmt: skip
    assert whole["X2"]["undefined"] is True
    assert summary["primary"] == "pipeline"
    assert "X4" in summary["bootstrap"]["head"]
    assert summary["pin_differences"] == {
        "head vs again": {"pipeline": 0, "refusal": 0, "side_effect": 0}
    }
    assert summary["harness"]["practice"] is True
    assert len(summary["harness"]["files_sha256"]) >= 6

    written = proc.stdout + (out / "agentdojo.rows.jsonl").read_text()
    written += (out / "agentdojo.summary.json").read_text()
    assert not any(marker in written for marker in TEXT_MARKERS)


def test_injecagent_zip_with_dotdot_is_not_evaluated(tmp_path: Path) -> None:
    data = tmp_path / "injecagent"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(MEMBER, json.dumps(injec_item(SUCC_OUTPUT)) + "\n")
        zf.writestr("results/../../escape.json", "{}")
    files = {"LICENCE": MIT.encode(), "TERMS": MIT.encode(), "results.zip": buf.getvalue()}
    manifest = fixture_dir(data, files, licence="LICENCE", terms="TERMS")
    proc = run_cli(tmp_path, "injecagent", data, manifest)
    assert proc.returncode == 3
    summary = json.loads((tmp_path / "out" / "injecagent.summary.json").read_text())
    assert summary["status"] == "not_evaluated"
    assert "member name" in summary["reason"]
    assert not (tmp_path / "out" / "injecagent.rows.jsonl").exists()


def test_data_inside_the_harness_folder_is_refused(tmp_path: Path) -> None:
    proc = python(
        "-I", str(RUN), "--benchmark", "agentdojo", "--data", str(PACKAGE / "downloads"),
        "--manifest", str(tmp_path / "m.json"), "--ziran-repo", str(REPO_ROOT),
        "--pin", "head=HEAD", "--out", str(tmp_path / "out"), "--practice",
        cwd=tmp_path,
    )  # fmt: skip
    assert proc.returncode == 2
    assert "harness folder" in proc.stderr


@pytest.mark.parametrize("specs", [["a=HEAD", "a=HEAD"], ["HEAD"], ["=HEAD"], ["a="]])
def test_pins_must_be_distinct_name_rev_pairs(specs: list[str]) -> None:
    with pytest.raises(HarnessError, match="NAME=REV"):
        _pins(REPO_ROOT, specs)


def test_a_second_run_into_the_same_output_is_refused(tmp_path: Path) -> None:
    data = tmp_path / "injecagent"
    manifest = fixture_dir(data, {"LICENCE": MIT.encode()}, licence="LICENCE")
    assert run_cli(tmp_path, "injecagent", data, manifest).returncode == 3
    again = run_cli(tmp_path, "injecagent", data, manifest)
    assert again.returncode == 2
    assert "already holds" in again.stderr


def test_output_inside_the_repo_and_not_ignored_is_refused(tmp_path: Path) -> None:
    proc = python(
        "-I", str(RUN), "--benchmark", "agentdojo", "--data", str(tmp_path),
        "--manifest", str(tmp_path / "m.json"), "--ziran-repo", str(REPO_ROOT),
        "--pin", "head=HEAD", "--out", str(REPO_ROOT / "benchmarks" / "results"), "--practice",
        cwd=tmp_path,
    )  # fmt: skip
    assert proc.returncode == 2
    assert "not git-ignored" in proc.stderr
