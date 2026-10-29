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
from benchmarks.external_eval.collect import Collected
from benchmarks.external_eval.intake import HarnessError
from benchmarks.external_eval.mapping import Unit
from benchmarks.external_eval.run import (
    EXPLORATORY_BELOW,
    WORKER_TIMEOUT,
    WorkerTimeoutError,
    _block,
    _bootstrap,
    _pin_differences,
    _pins,
    _worker,
)
from tests.unit.test_external_eval_mapping import (
    AGENTDOJO_REL,
    MEMBER,
    MIT,
    SUCC_OUTPUT,
    UNSUCC_OUTPUT,
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
    *args: str, cwd: Path | None = None, stdin: str = "", env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        input=stdin,
        cwd=cwd,
        env={**isolation.worker_env(), **(env or {})},
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
        f"import sys; sys.path.insert(0, {str(PACKAGE)!r}); import worker; worker.block_network()\n"
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
    tmp_path: Path,
    benchmark: str,
    data: Path,
    manifest: Path,
    *extra: str,
    env: dict[str, str] | None = None,
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
        *extra,
        cwd=tmp_path,
        env=env,
    )  # fmt: skip


def git_sha256(rev: str, rel: str) -> str:
    """sha256 of a file at a commit, computed apart from the harness."""
    blob = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", f"{rev}:{rel}"], capture_output=True, check=True
    ).stdout
    return hashlib.sha256(blob).hexdigest()


def rows_of(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


REFUSING = "I'm sorry, but I can't help with that."


def refusing_log(**over: Any) -> dict[str, Any]:
    log = agentdojo_log(**over)
    log["messages"] = [*log["messages"][:2], {"role": "assistant", "content": REFUSING}]
    return log


def test_agentdojo_fixture_end_to_end(tmp_path: Path) -> None:
    data = tmp_path / "agentdojo"
    no_marker = agentdojo_log()
    no_marker["messages"][5]["content"] = "file: plain"
    error_rel = AGENTDOJO_REL.replace("task_1", "task_3")
    negative_rel = AGENTDOJO_REL.replace("task_1", "task_4")
    files = {
        "LICENSE": MIT.encode(),
        AGENTDOJO_REL: json.dumps(agentdojo_log()).encode(),
        AGENTDOJO_REL.replace("task_1", "task_2"): json.dumps(no_marker).encode(),
        error_rel: json.dumps(refusing_log(error="server error")).encode(),
        negative_rel: json.dumps(refusing_log(security=False)).encode(),
    }
    manifest = fixture_dir(data, files, licence="LICENSE")
    leak = {"ZZ_LEAK": "1", "FAKE_API_KEY": "not-a-key"}
    proc = run_cli(tmp_path, "agentdojo", data, manifest, "--expect-split", "4", env=leak)
    assert proc.returncode == 0, proc.stdout
    out = tmp_path / "out"
    rows = rows_of(out / "agentdojo.rows.jsonl")
    assert len(rows) == 24
    for row in rows:
        assert set(row) == {
            "benchmark", "pin", "unit_id", "variant", "label", "excluded", "cells",
            "refusal", "side_effect", "pipeline",
        }  # fmt: skip
        assert all(isinstance(row[k], bool) for k in ("refusal", "side_effect", "pipeline"))
    variants = {(r["unit_id"], r["variant"]): r for r in rows if r["pin"] == "head"}
    assert variants[(AGENTDOJO_REL, "text_only")]["pipeline"] is False
    assert variants[(AGENTDOJO_REL, "post_injection")]["side_effect"] is True
    # refusal fires on no refusal language, and not on a refusal
    assert variants[(AGENTDOJO_REL, "whole")]["refusal"] is True
    assert variants[(negative_rel, "whole")]["refusal"] is False
    assert variants[(negative_rel, "whole")]["label"] is False
    assert variants[(error_rel, "whole")]["excluded"] == "error"
    assert variants[(error_rel, "whole")]["label"] is None

    summary = json.loads((out / "agentdojo.summary.json").read_text())
    assert summary["status"] == "evaluated"
    assert summary["intake"]["counts"]["no_marker"] == 3
    assert summary["intake"]["counts"]["excluded:error"] == 1
    assert summary["intake"]["spdx"] == "MIT"
    pin = summary["pins"]["head"]
    assert set(pin["files_sha256"]) == set(isolation.PINNED_FILES)
    assert pin["defaults"]["thresholds"]["hit"] == 0.7
    assert pin["defaults"]["config"]["refusal_matchtype"] == "str"
    assert pin["modules_checked"] == len(pin["modules_sha256"]) > len(isolation.PINNED_FILES)
    assert "ziran/application/detectors/ensemble.py" in pin["modules_sha256"]
    assert pin["environment"]["python"] == summary["harness"]["python"]
    assert 0 < pin["worker_wall_seconds"] < 300
    assert summary["run_settings"] == {
        "worker_timeout_seconds": 3600.0,
        "expect_split": 4,
        "expect_harness": None,
    }
    # hashes are the files' own, computed apart from the harness
    assert pin["sha"] == summary["harness"]["commit"] == git_rev("HEAD")
    for rel in isolation.PINNED_FILES:
        assert pin["files_sha256"][rel] == git_sha256("HEAD", rel)
    for rel in ("ziran/application/detectors/pipeline.py", "ziran/domain/tool_classifier.py"):
        assert pin["modules_sha256"][rel] == git_sha256("HEAD", rel)
    run_py = "benchmarks/external_eval/run.py"
    assert (
        summary["harness"]["files_sha256"][run_py] == hashlib.sha256(RUN.read_bytes()).hexdigest()
    )
    assert summary["manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    rows_bytes = (out / "agentdojo.rows.jsonl").read_bytes()
    assert summary["rows_sha256"] == hashlib.sha256(rows_bytes).hexdigest()
    # the key-like variable is removed and counted; the worker sees only the allow-list
    assert summary["environment_variables_removed"] == 1
    assert "PYTHONHASHSEED" in pin["environment"]["variables"]
    assert not {"ZZ_LEAK", "FAKE_API_KEY"} & set(pin["environment"]["variables"])
    assert pin["environment"]["installed_sha256"] == summary["harness"]["installed_sha256"]
    # the excluded error log counts nowhere: two positives and one negative are analysed
    whole = summary["metrics"]["head"]["whole"]["pipeline"]["all"]
    assert whole["confusion"] == {"tp": 2, "fn": 0, "fp": 0, "tn": 1}
    assert (whole["X2"]["k"], whole["X2"]["n"]) == (1, 1)
    assert (whole["X3"]["k"], whole["X3"]["n"]) == (2, 2)
    refusal = summary["metrics"]["head"]["whole"]["refusal"]["all"]
    assert refusal["confusion"] == {"tp": 2, "fn": 0, "fp": 0, "tn": 1}
    assert summary["primary"] == "pipeline"
    assert summary["bootstrap"]["head"]["X2"] == [1.0, 1.0]
    assert summary["pin_differences"] == {
        "head vs again": {"pipeline": 0, "refusal": 0, "side_effect": 0}
    }
    assert summary["harness"]["practice"] is True
    assert len(summary["harness"]["files_sha256"]) >= 6

    written = proc.stdout + proc.stderr + (out / "agentdojo.rows.jsonl").read_text()
    written += (out / "agentdojo.summary.json").read_text()
    assert not any(marker in written for marker in (*TEXT_MARKERS, "sorry"))


def test_injecagent_fixture_bootstraps_the_refusal_row(tmp_path: Path) -> None:
    data = tmp_path / "injecagent"
    buf = io.BytesIO()
    lines = [injec_item(SUCC_OUTPUT), injec_item(UNSUCC_OUTPUT), injec_item("too short")]
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(MEMBER, "".join(json.dumps(item) + "\n" for item in lines))
    files = {"LICENCE": MIT.encode(), "TERMS": MIT.encode(), "results.zip": buf.getvalue()}
    proc = run_cli(
        tmp_path, "injecagent", data, fixture_dir(data, files, licence="LICENCE", terms="TERMS")
    )
    assert proc.returncode == 0, proc.stdout
    summary = json.loads((tmp_path / "out" / "injecagent.summary.json").read_text())
    assert summary["primary"] == "refusal"
    metrics = summary["metrics"]["head"]["whole"]
    assert metrics["refusal"]["all"]["confusion"] == {"tp": 1, "fn": 0, "fp": 0, "tn": 1}
    assert metrics["pipeline"]["all"]["confusion"] == {"tp": 0, "fn": 1, "fp": 0, "tn": 1}
    # the refusal row's interval, not the pipeline's
    assert summary["bootstrap"]["head"]["X1"] == [1.0, 1.0]
    assert summary["intake"]["counts"]["excluded:invalid"] == 1


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


def test_a_damaged_member_with_injection_text_in_its_name_stays_off_stderr(tmp_path: Path) -> None:
    from tests.unit.test_external_eval_intake import _damaged

    data = tmp_path / "injecagent"
    files = {"LICENCE": MIT.encode(), "TERMS": MIT.encode(), "results.zip": _damaged("crc")}
    proc = run_cli(
        tmp_path, "injecagent", data, fixture_dir(data, files, licence="LICENCE", terms="TERMS")
    )
    assert proc.returncode == 3
    summary = (tmp_path / "out" / "injecagent.summary.json").read_text()
    assert "archive member 0: unreadable (BadZipFile)" in summary
    assert "IGNORE" not in proc.stdout + proc.stderr + summary


def test_output_inside_the_repo_and_not_ignored_is_refused(tmp_path: Path) -> None:
    proc = python(
        "-I", str(RUN), "--benchmark", "agentdojo", "--data", str(tmp_path),
        "--manifest", str(tmp_path / "m.json"), "--ziran-repo", str(REPO_ROOT),
        "--pin", "head=HEAD", "--out", str(REPO_ROOT / "benchmarks" / "results"), "--practice",
        cwd=tmp_path,
    )  # fmt: skip
    assert proc.returncode == 2
    assert "not git-ignored" in proc.stderr


# ── worker on a hand-made stand-in export ─────────────────────────────

_FAKE = {
    "ziran/__init__.py": "",
    "ziran/application/__init__.py": "",
    "ziran/application/detectors/__init__.py": "",
    "ziran/domain/__init__.py": "",
    "ziran/domain/entities/__init__.py": "",
    "ziran/domain/interfaces/__init__.py": "",
    "ziran/application/detectors/thresholds.py": (
        "class DetectorThresholds:\n    hit = 0.7\n"
        "    def model_dump(self, mode=None):\n        return {'hit': self.hit}\n"
    ),
    "ziran/domain/entities/attack.py": (
        "class AttackPrompt:\n    def __init__(self, **kw):\n        self.__dict__.update(kw)\n"
    ),
    "ziran/domain/interfaces/adapter.py": (
        "class AgentResponse:\n    def __init__(self, **kw):\n        self.__dict__.update(kw)\n"
    ),
    "ziran/application/detectors/pipeline.py": """
import dataclasses, json, sys, types

@dataclasses.dataclass
class DetectorConfig:
    refusal_matchtype: str = "str"

class _R:
    def __init__(self, name, score):
        self.detector_name, self.score = name, score

class _V:
    def __init__(self, successful, results):
        self.successful, self.detector_results = successful, results

class DetectorPipeline:
    def __init__(self, detector_config=None):
        pass

    async def evaluate(self, prompt, response, spec, vector):
        s = json.loads(response.content) if response.content.startswith("{") else {}
        if s.get("plant"):
            m = types.ModuleType("ziran.planted")
            m.__file__ = "/elsewhere/planted.py"
            sys.modules["ziran.planted"] = m
        if s.get("sleep"):
            import time
            time.sleep(s["sleep"])
        if s.get("fdwrite"):
            import os
            os.write(1, b"junk on fd 1\\n")
        if s.get("connect"):
            import socket
            socket.socket().connect(("127.0.0.1", 9))
        return _V(
            s.get("pipeline", False),
            [_R("refusal", s.get("refusal", 1.0)), _R("side_effect", s.get("side_effect", 0.0))],
        )
""",
}


def fake_worker(tmp_path: Path, *scores: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    root = tmp_path / "export"
    for rel, text in _FAKE.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    stdin = "".join(
        json.dumps({"key": i, "prompt": "p", "content": json.dumps(s), "tool_calls": []}) + "\n"
        for i, s in enumerate(scores)
    )
    return python("-I", str(WORKER), str(root), cwd=tmp_path, stdin=stdin)


def test_worker_predictors_fire_at_hit_and_above(tmp_path: Path) -> None:
    proc = fake_worker(
        tmp_path,
        {"refusal": 0.69, "side_effect": 0.69, "pipeline": False},
        {"refusal": 0.7, "side_effect": 0.7, "pipeline": True},
        {"refusal": 0.0, "side_effect": 1.0, "pipeline": True},
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(x) for x in proc.stdout.splitlines()]
    verdicts = [(v["refusal"], v["side_effect"], v["pipeline"]) for v in lines[1:-1]]
    assert verdicts == [(False, False, False), (True, True, True), (False, True, True)]
    assert lines[0]["header"]["thresholds"] == {"hit": 0.7}
    assert set(lines[-1]["module_sha256"]) == {r for r in _FAKE if r.endswith(".py")}


def test_worker_blocks_sockets_inside_the_pinned_code(tmp_path: Path) -> None:
    proc = fake_worker(
        tmp_path, {"connect": True, "refusal": 1, "side_effect": 0, "pipeline": False}
    )
    assert proc.returncode != 0
    assert "socket.connect is blocked" in proc.stderr


def test_worker_rechecks_modules_at_the_end(tmp_path: Path) -> None:
    proc = fake_worker(tmp_path, {"plant": True, "refusal": 1, "side_effect": 0, "pipeline": False})
    assert proc.returncode != 0
    assert "ziran.planted resolves outside the export" in proc.stderr


def test_worker_blocks_child_processes(tmp_path: Path) -> None:
    code = (
        f"import sys; sys.path.insert(0, {str(PACKAGE)!r}); import worker; worker.block_network()\n"
        "import subprocess\n"
        "try:\n    subprocess.run(['true'])\nexcept RuntimeError as exc:\n    print(exc)\n"
    )
    assert python("-I", "-c", code, cwd=tmp_path).stdout.strip() == "subprocess.Popen is blocked"


# ── harness record, pins and summary helpers ──────────────────────────


def test_pinned_files_are_the_seven_of_section_1_and_uv_lock() -> None:
    assert isolation.PINNED_FILES == (
        "ziran/application/detectors/pipeline.py",
        "ziran/application/detectors/refusal.py",
        "ziran/application/detectors/indicator.py",
        "ziran/application/detectors/side_effect.py",
        "ziran/application/detectors/authorization.py",
        "ziran/application/detectors/thresholds.py",
        "ziran/domain/tool_classifier.py",
        "uv.lock",
    )


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        check=True, capture_output=True,
    )  # fmt: skip


def test_harness_record_refuses_uncommitted_harness_files(tmp_path: Path) -> None:
    repo = tmp_path / "h"
    (repo / isolation.HARNESS_DIR).mkdir(parents=True)
    (repo / isolation.HARNESS_DIR / "a.py").write_text("x = 1\n")
    (repo / "uv.lock").write_text("lock\n")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "c")
    assert isolation.harness_record(repo, practice=False)["frozen"] is True
    (repo / isolation.HARNESS_DIR / "a.py").write_text("x = 2\n")
    with pytest.raises(HarnessError, match="differ from the commit"):
        isolation.harness_record(repo, practice=False)
    assert isolation.harness_record(repo, practice=True)["frozen"] is False


def test_a_partial_clone_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    isolation.require_full_clone(repo)
    _git(repo, "config", "extensions.partialClone", "origin")
    with pytest.raises(HarnessError, match="partial clone"):
        isolation.require_full_clone(repo)


def _unit(variant: str, cluster: str, label: bool) -> Unit:
    return Unit(
        benchmark="b", unit_id=cluster, variant=variant, prompt="", content="", tool_calls=[],
        label=label, excluded=None, cluster=cluster, cells={},
    )  # fmt: skip


def test_bootstrap_takes_the_given_predictor_on_the_whole_row() -> None:
    units = Collected(
        units=[_unit("whole", "a", True), _unit("text_only", "a", True)],
        counts={}, spdx="MIT", terms_spdx=None, manifest_files=1, extra_hashes={},
    )  # fmt: skip
    verdicts = [
        {"refusal": True, "pipeline": False, "side_effect": False},
        {"refusal": False, "pipeline": False, "side_effect": False},
    ]
    assert _bootstrap(units, verdicts, "refusal")["X1"] == [1.0, 1.0]
    assert _bootstrap(units, verdicts, "pipeline")["X1"] == [0.0, 0.0]


def test_pin_differences_count_each_predictor() -> None:
    a = [{"refusal": True, "side_effect": False, "pipeline": False}] * 2
    b = [{"refusal": False, "side_effect": False, "pipeline": True}, a[0]]
    assert _pin_differences({"v1": a, "v0": b}) == {
        "v1 vs v0": {"refusal": 1, "side_effect": 0, "pipeline": 1}
    }


def test_run_refuses_when_ziran_is_already_loaded(tmp_path: Path) -> None:
    code = (
        f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r}); import ziran\n"
        "from benchmarks.external_eval.run import main; sys.exit(main(['--help']))\n"
    )
    proc = python("-I", "-c", code, cwd=tmp_path)
    assert proc.returncode == 2
    assert "ziran is loaded" in proc.stderr


def git_rev(rev: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", rev], capture_output=True, text=True, check=True
    ).stdout.strip()


# ── fix round 2 ───────────────────────────────────────────────────────


def test_worker_writes_to_fd_1_never_reach_the_verdict_stream(tmp_path: Path) -> None:
    proc = fake_worker(
        tmp_path, {"fdwrite": True, "refusal": 1, "side_effect": 0, "pipeline": False}
    )
    assert proc.returncode == 0, proc.stderr
    assert "junk" not in proc.stdout
    assert "junk on fd 1" in proc.stderr


@pytest.mark.parametrize(
    ("code", "event"),
    [
        ("import ctypes; ctypes.CDLL(None)", "ctypes.dlopen"),
        ("import os; os.execv('/bin/echo', ['echo', 'ran'])", "os.exec"),
        ("import os; os.system('echo ran')", "os.system"),
    ],
)
def test_worker_blocks_c_libraries_and_exec(tmp_path: Path, code: str, event: str) -> None:
    prelude = (
        f"import sys; sys.path.insert(0, {str(PACKAGE)!r}); import worker; worker.block_network()\n"
    )
    proc = python("-I", "-c", prelude + code, cwd=tmp_path)
    assert f"{event} is blocked" in proc.stderr
    assert "ran" not in proc.stdout


def test_the_harness_process_blocks_the_network(tmp_path: Path) -> None:
    code = (
        f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "from benchmarks.external_eval import run\n"
        "def probe(args, removed):\n"
        "    import socket; socket.socket().connect(('127.0.0.1', 9)); return 0\n"
        "run.run = probe\n"
        "sys.exit(run.main(['--benchmark', 'agentdojo', '--data', 'd', '--manifest', 'm',"
        " '--ziran-repo', 'r', '--pin', 'a=HEAD', '--out', 'o']))\n"
    )
    assert "socket.connect is blocked" in python("-I", "-c", code, cwd=tmp_path).stderr


def test_data_inside_the_repo_and_not_ignored_is_refused(tmp_path: Path) -> None:
    proc = python(
        "-I", str(RUN), "--benchmark", "agentdojo", "--data", str(REPO_ROOT / "benchmarks" / "results"),
        "--manifest", str(tmp_path / "m.json"), "--ziran-repo", str(REPO_ROOT),
        "--pin", "head=HEAD", "--out", str(tmp_path / "out"), "--practice",
        cwd=tmp_path,
    )  # fmt: skip
    assert proc.returncode == 2
    assert "not git-ignored" in proc.stderr


def test_output_inside_another_ziran_clone_is_refused(tmp_path: Path) -> None:
    other = tmp_path / "ziran"
    other.mkdir()
    _git(other, "init", "-q")
    proc = python(
        "-I", str(RUN), "--benchmark", "agentdojo", "--data", str(tmp_path),
        "--manifest", str(tmp_path / "m.json"), "--ziran-repo", str(other),
        "--pin", "head=HEAD", "--out", str(other / "out"), "--practice",
        cwd=tmp_path,
    )  # fmt: skip
    assert proc.returncode == 2
    assert "not git-ignored" in proc.stderr


def _small_repo(tmp_path: Path) -> tuple[Path, str]:
    src = tmp_path / "src"
    src.mkdir()
    _git(src, "init", "-q")
    _git(src, "config", "uploadpack.allowFilter", "true")
    (src / "f.txt").write_text("one\n")
    _git(src, "add", "-A")
    _git(src, "commit", "-qm", "one")
    first = subprocess.run(
        ["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    (src / "f.txt").write_text("two\n")
    _git(src, "commit", "-qam", "two")
    return src, first


def test_a_real_blobless_clone_is_refused_and_never_fetches(tmp_path: Path) -> None:
    src, first = _small_repo(tmp_path)
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", "--filter=blob:none", f"file://{src}", str(clone)],
        check=True, capture_output=True,
    )  # fmt: skip
    with pytest.raises(HarnessError, match="partial clone"):
        isolation.require_full_clone(clone)
    with pytest.raises(HarnessError, match="git archive failed"):
        isolation.export_pin(clone, first, tmp_path / "export")
    full = tmp_path / "full"
    subprocess.run(["git", "clone", "-q", str(src), str(full)], check=True, capture_output=True)
    isolation.require_full_clone(full)
    isolation.export_pin(full, first, tmp_path / "export-full")
    assert (tmp_path / "export-full" / "f.txt").read_text() == "one\n"


def test_export_refuses_a_link_out_of_the_tree(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "evil").symlink_to("/etc/passwd")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "c")
    with pytest.raises(HarnessError, match="data filter"):
        isolation.export_pin(repo, "HEAD", tmp_path / "export")


def test_cells_under_fifty_units_are_exploratory() -> None:
    assert EXPLORATORY_BELOW == 50
    assert _block([(True, True)] * 49)["exploratory"] is True
    assert _block([(True, True)] * 50)["exploratory"] is False


def _small_agentdojo(tmp_path: Path) -> tuple[Path, Path]:
    data = tmp_path / "agentdojo"
    files = {"LICENSE": MIT.encode(), AGENTDOJO_REL: json.dumps(agentdojo_log()).encode()}
    return data, fixture_dir(data, files, licence="LICENSE")


def test_an_unexpected_split_is_not_evaluated(tmp_path: Path) -> None:
    data, manifest = _small_agentdojo(tmp_path)
    proc = run_cli(tmp_path, "agentdojo", data, manifest, "--expect-split", "2")
    assert proc.returncode == 3
    summary = json.loads((tmp_path / "out" / "agentdojo.summary.json").read_text())
    assert "split holds 1 units" in summary["reason"]
    assert summary["run_settings"]["expect_split"] == 2


@pytest.mark.parametrize("value", ["0000000", "abc"])
def test_an_unexpected_harness_commit_is_refused(tmp_path: Path, value: str) -> None:
    data, manifest = _small_agentdojo(tmp_path)
    proc = run_cli(tmp_path, "agentdojo", data, manifest, "--expect-harness", value)
    assert proc.returncode == 2
    assert "harness commit differs" in proc.stderr
    assert not (tmp_path / "out" / "agentdojo.summary.json").exists()


@pytest.mark.parametrize("kind", ["cd_offset", "local_name", "version", "cd_name"])
def test_a_damaged_zip_header_is_not_evaluated(tmp_path: Path, kind: str) -> None:
    from tests.unit.test_external_eval_intake import damaged_header

    data = tmp_path / "injecagent"
    files = {"LICENCE": MIT.encode(), "TERMS": MIT.encode(), "results.zip": damaged_header(kind)}
    proc = run_cli(
        tmp_path, "injecagent", data, fixture_dir(data, files, licence="LICENCE", terms="TERMS")
    )
    assert proc.returncode == 3, proc.stderr[-300:]
    summary = json.loads((tmp_path / "out" / "injecagent.summary.json").read_text())
    assert summary["status"] == "not_evaluated"
    assert "Traceback" not in proc.stderr


def test_an_expected_harness_value_must_be_a_prefix(tmp_path: Path) -> None:
    data, manifest = _small_agentdojo(tmp_path)
    proc = run_cli(tmp_path, "agentdojo", data, manifest, "--expect-harness", git_rev("HEAD")[1:13])
    assert proc.returncode == 2


def test_installed_sha256_is_the_sorted_distribution_list() -> None:
    from importlib import metadata

    lines = sorted(
        f"{(d.metadata['Name'] or '').lower()}=={d.version}" for d in metadata.distributions()
    )
    expected = hashlib.sha256("\n".join(lines).encode()).hexdigest()
    assert isolation.worker.installed_sha256() == expected
    assert expected != hashlib.sha256(b"").hexdigest()


def test_an_unreadable_git_config_is_a_refusal(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / ".git" / "config").write_text("[[[ not a config\n")
    with pytest.raises(HarnessError, match="git config"):
        isolation.require_full_clone(repo)


def test_a_short_expected_harness_prefix_is_not_enough(tmp_path: Path) -> None:
    data, manifest = _small_agentdojo(tmp_path)
    proc = run_cli(tmp_path, "agentdojo", data, manifest, "--expect-harness", git_rev("HEAD")[:6])
    assert proc.returncode == 2


def test_output_inside_the_harness_repo_is_refused_with_another_ziran_clone(tmp_path: Path) -> None:
    other = tmp_path / "ziran"
    other.mkdir()
    _git(other, "init", "-q")
    proc = python(
        "-I", str(RUN), "--benchmark", "agentdojo", "--data", str(tmp_path),
        "--manifest", str(tmp_path / "m.json"), "--ziran-repo", str(other),
        "--pin", "head=HEAD", "--out", str(REPO_ROOT / "benchmarks" / "results"), "--practice",
        cwd=tmp_path,
    )  # fmt: skip
    assert proc.returncode == 2
    assert "not git-ignored" in proc.stderr


def test_the_expected_harness_commit_runs(tmp_path: Path) -> None:
    data, manifest = _small_agentdojo(tmp_path)
    proc = run_cli(tmp_path, "agentdojo", data, manifest, "--expect-harness", git_rev("HEAD")[:12])
    assert proc.returncode == 0, proc.stdout


# ── round 4: fail closed at the boundary, worker timeout ──────────────


def test_an_unexpected_collect_error_is_not_evaluated_with_its_type_only(tmp_path: Path) -> None:
    data, manifest = _small_agentdojo(tmp_path)
    code = (
        f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "from benchmarks.external_eval import run\n"
        "def broken(*a, **k):\n    raise KeyError('SECRET-INPUT-TEXT')\n"
        "run.collect = broken\n"
        f"sys.exit(run.main(['--benchmark', 'agentdojo', '--data', {str(data)!r},"
        f" '--manifest', {str(manifest)!r}, '--ziran-repo', {str(REPO_ROOT)!r},"
        f" '--pin', 'head=HEAD', '--out', {str(tmp_path / 'out')!r}, '--practice']))\n"
    )
    proc = python("-I", "-c", code, cwd=tmp_path)
    assert proc.returncode == 3, proc.stderr[-300:]
    text = (tmp_path / "out" / "agentdojo.summary.json").read_text()
    assert json.loads(text)["reason"] == "collect: KeyError"
    assert "SECRET" not in text + proc.stdout + proc.stderr


def test_a_worker_past_its_timeout_is_killed(tmp_path: Path) -> None:
    root = tmp_path / "export"
    for rel, text in _FAKE.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    unit = _unit("whole", "a", True).model_copy(
        update={
            "content": json.dumps({"sleep": 30, "refusal": 1, "side_effect": 0, "pipeline": False})
        }
    )
    units = Collected(
        units=[unit], counts={}, spdx="MIT", terms_spdx=None, manifest_files=1, extra_hashes={}
    )
    import time

    start = time.monotonic()
    with pytest.raises(WorkerTimeoutError):
        _worker(root, tmp_path, units, timeout=2)
    assert time.monotonic() - start < 20


def test_a_run_whose_worker_times_out_stops_with_no_summary(tmp_path: Path) -> None:
    assert WORKER_TIMEOUT == 3600.0
    data, manifest = _small_agentdojo(tmp_path)
    proc = run_cli(tmp_path, "agentdojo", data, manifest, "--worker-timeout", "0.01")
    assert proc.returncode == 2
    assert "worker timed out after 0.01 s" in proc.stderr
    assert not (tmp_path / "out" / "agentdojo.summary.json").exists()
    assert not (tmp_path / "out" / "agentdojo.rows.jsonl").exists()


# ── round 5: no pipes to the worker, timeouts stop the run ────────────


def _fake_pin_repo(tmp_path: Path) -> tuple[Path, str, str]:
    """A git repo holding the stand-in ziran: commit A scores, commit B stalls at import."""
    repo = tmp_path / "pins"
    for rel, text in _FAKE.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "scores")
    good = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    pipeline = repo / "ziran/application/detectors/pipeline.py"
    pipeline.write_text("import time\ntime.sleep(120)\n" + pipeline.read_text())
    _git(repo, "commit", "-qam", "stalls")
    stall = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    return repo, good, stall


def _run_pins(tmp_path: Path, repo: Path, *pins: str) -> subprocess.CompletedProcess[str]:
    data, manifest = _small_agentdojo(tmp_path)
    args = [a for pin in pins for a in ("--pin", pin)]
    return python(
        "-I", str(RUN), "--benchmark", "agentdojo", "--data", str(data),
        "--manifest", str(manifest), "--ziran-repo", str(repo), *args,
        "--out", str(tmp_path / "out"), "--practice", "--worker-timeout", "3",
        cwd=tmp_path,
    )  # fmt: skip


def test_a_stalled_worker_stops_the_run_within_its_timeout(tmp_path: Path) -> None:
    import time

    repo, _good, stall = _fake_pin_repo(tmp_path)
    start = time.monotonic()
    proc = _run_pins(tmp_path, repo, f"a={stall}")
    assert time.monotonic() - start < 30
    assert proc.returncode == 2
    assert "worker timed out after 3 s" in proc.stderr
    assert not (tmp_path / "out" / "agentdojo.summary.json").exists()


def test_a_second_pin_that_times_out_writes_no_summary_and_no_rows(tmp_path: Path) -> None:
    repo, good, stall = _fake_pin_repo(tmp_path)
    first = _run_pins(tmp_path / "one", repo, f"a={good}")
    assert first.returncode == 0, first.stderr[-300:]
    proc = _run_pins(tmp_path, repo, f"a={good}", f"b={stall}")
    assert proc.returncode == 2
    assert not (tmp_path / "out" / "agentdojo.summary.json").exists()
    assert not (tmp_path / "out" / "agentdojo.rows.jsonl").exists()


def test_a_worker_flooding_stderr_before_reading_a_large_input_never_hangs(
    tmp_path: Path,
) -> None:
    root = tmp_path / "export"
    for rel, text in _FAKE.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    pipeline = root / "ziran/application/detectors/pipeline.py"
    pipeline.write_text("import sys\nsys.stderr.write('e' * 200_000)\n" + pipeline.read_text())
    code = f"""
import json, sys
sys.path.insert(0, {str(REPO_ROOT)!r})
from pathlib import Path
from benchmarks.external_eval.collect import Collected
from benchmarks.external_eval.mapping import Unit
from benchmarks.external_eval.run import _worker
unit = Unit(benchmark="b", unit_id="u", variant="whole", prompt="p", content="x" * 100_000,
            tool_calls=[], label=True, excluded=None, cluster="c", cells={{}})
units = Collected(units=[unit] * 3, counts={{}}, spdx="MIT", terms_spdx=None,
                  manifest_files=1, extra_hashes={{}})
header, verdicts = _worker(Path({str(root)!r}), Path({str(tmp_path)!r}), units, 60)
print(len(verdicts))
"""
    proc = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True, text=True, timeout=120, env=isolation.worker_env(), check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr[-300:]
    assert proc.stdout.strip() == "3"


def test_an_unexpected_manifest_error_names_the_manifest_phase(tmp_path: Path) -> None:
    data, manifest = _small_agentdojo(tmp_path)
    code = (
        f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "from benchmarks.external_eval import run\n"
        "def broken(*a, **k):\n    raise KeyError('SECRET-INPUT-TEXT')\n"
        "run.read_manifest = broken\n"
        f"sys.exit(run.main(['--benchmark', 'agentdojo', '--data', {str(data)!r},"
        f" '--manifest', {str(manifest)!r}, '--ziran-repo', {str(REPO_ROOT)!r},"
        f" '--pin', 'head=HEAD', '--out', {str(tmp_path / 'out')!r}, '--practice']))\n"
    )
    proc = python("-I", "-c", code, cwd=tmp_path)
    assert proc.returncode == 3, proc.stderr[-300:]
    text = (tmp_path / "out" / "agentdojo.summary.json").read_text()
    assert json.loads(text)["reason"] == "manifest: KeyError"
    assert "SECRET" not in text + proc.stdout + proc.stderr
