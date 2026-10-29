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
from benchmarks.external_eval.run import _bootstrap, _pin_differences, _pins
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
    proc = run_cli(tmp_path, "agentdojo", data, fixture_dir(data, files, licence="LICENSE"))
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
        s = json.loads(response.content)
        if s.get("plant"):
            m = types.ModuleType("ziran.planted")
            m.__file__ = "/elsewhere/planted.py"
            sys.modules["ziran.planted"] = m
        if s.get("connect"):
            import socket
            socket.socket().connect(("127.0.0.1", 9))
        return _V(s["pipeline"], [_R("refusal", s["refusal"]), _R("side_effect", s["side_effect"])])
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
