"""Record-and-replay model client tests (spec 064)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ziran.infrastructure.llm.base import PendingResponse
from ziran.infrastructure.llm.replay_client import RecordReplayClient, request_key

PROMPT = "Judge this trace.\n\n{input}\n"
MODEL = "gpt-5.6-luna"
VERSION = "codex-cli 0.163.0"
TEXT = "Judge this trace.\n\ncall 0: send_money(iban=XX)\n"


def _user(text: str) -> list[dict[str, str]]:
    return [{"role": "user", "content": text}]


# ── Request key (acceptance 1) ───────────────────────────────────────


@pytest.mark.unit
def test_the_same_four_give_the_same_key() -> None:
    key = request_key(PROMPT, MODEL, VERSION, TEXT)
    assert key == request_key(PROMPT, MODEL, VERSION, TEXT)
    assert len(key) == 64 and int(key, 16) >= 0


@pytest.mark.unit
def test_the_key_is_stable_across_runs() -> None:
    # sha256 over each part as an 8-byte big-endian length, then its UTF-8 bytes
    assert request_key("p", "m", "v", "t") == (
        "b7b0e67a9d96fc56d991ce89d46d647b1c54408b6e6fb7f1201d522d7664d923"
    )


@pytest.mark.unit
@pytest.mark.parametrize("part", range(4))
def test_one_changed_byte_in_any_part_changes_the_key(part: int) -> None:
    parts = [PROMPT, MODEL, VERSION, TEXT]
    changed = list(parts)
    changed[part] = parts[part][:-1] + chr(ord(parts[part][-1]) ^ 1)
    assert request_key(*changed) != request_key(*parts)


@pytest.mark.unit
def test_moving_a_byte_between_parts_changes_the_key() -> None:
    assert request_key("ab", "c", "v", "t") != request_key("a", "bc", "v", "t")


# ── Record (acceptance 2) ────────────────────────────────────────────


def _blocked(*_: object, **__: object) -> None:
    raise AssertionError("a socket or process was opened")


@pytest.mark.unit
def test_record_writes_one_line_opens_no_socket_and_returns_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "judge.requests.jsonl"
    client = RecordReplayClient(MODEL, VERSION, record_to=out)
    loop = asyncio.new_event_loop()  # its self-pipe exists before sockets are blocked
    monkeypatch.setattr(socket.socket, "__init__", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(subprocess.Popen, "__init__", _blocked)
    try:
        result = loop.run_until_complete(
            client.complete(_user(TEXT), job="trace_judge", unit="u-1", prompt=PROMPT)
        )
    finally:
        loop.close()
    assert isinstance(result, PendingResponse)
    assert result.reason == "recorded" and result.content == ""
    lines = out.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in lines] == [
        {
            "key": request_key(PROMPT, MODEL, VERSION, TEXT),
            "job": "trace_judge",
            "unit": "u-1",
            "text": TEXT,
        }
    ]


@pytest.mark.unit
async def test_record_appends_and_writes_a_key_once(tmp_path: Path) -> None:
    out = tmp_path / "judge.requests.jsonl"
    client = RecordReplayClient(MODEL, VERSION, record_to=out)
    await client.complete(_user(TEXT), job="trace_judge", unit="u-1", prompt=PROMPT)
    await client.complete(_user(TEXT), job="trace_judge", unit="u-2", prompt=PROMPT)
    await client.complete(_user(TEXT + "x"), job="trace_judge", unit="u-3", prompt=PROMPT)
    # a second client on the same file keeps the keys already there
    again = RecordReplayClient(MODEL, VERSION, record_to=out)
    await again.complete(_user(TEXT), job="trace_judge", unit="u-4", prompt=PROMPT)
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert [r["unit"] for r in rows] == ["u-1", "u-3"]


@pytest.mark.unit
async def test_a_text_with_a_line_separator_stays_one_line(tmp_path: Path) -> None:
    out = tmp_path / "judge.requests.jsonl"
    text = "tool result:\u2028second\u2029third\x85end"
    await RecordReplayClient(MODEL, VERSION, record_to=out).complete(
        _user(text), job="trace_judge", unit="u-1", prompt=PROMPT
    )
    await RecordReplayClient(MODEL, VERSION, record_to=out).complete(
        _user(text), job="trace_judge", unit="u-2", prompt=PROMPT
    )
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").split("\n") if line]
    assert [(r["unit"], r["text"]) for r in rows] == [("u-1", text)]


@pytest.mark.unit
def test_a_planted_link_at_the_request_path_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.txt"
    target.write_text("keep\n")
    link = tmp_path / "judge.requests.jsonl"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        RecordReplayClient(MODEL, VERSION, record_to=link)
    assert target.read_text() == "keep\n"


@pytest.mark.unit
def test_a_dangling_link_at_the_request_path_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "not-yet.txt"
    link = tmp_path / "judge.requests.jsonl"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        RecordReplayClient(MODEL, VERSION, record_to=link)
    assert not target.exists()


@pytest.mark.unit
def test_a_linked_parent_folder_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "linked").symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        RecordReplayClient(MODEL, VERSION, record_to=tmp_path / "linked" / "j.requests.jsonl")
    assert list(real.iterdir()) == []


@pytest.mark.unit
async def test_a_link_above_the_folder_is_resolved_and_accepted(tmp_path: Path) -> None:
    """macOS /tmp is a link to /private/tmp: a link above the caller's folder is allowed."""
    real = tmp_path / "private"
    (real / "work").mkdir(parents=True)
    (tmp_path / "tmp").symlink_to(real, target_is_directory=True)
    client = RecordReplayClient(
        MODEL, VERSION, record_to=tmp_path / "tmp" / "work" / "j.requests.jsonl"
    )
    await client.complete(_user(TEXT), job="trace_judge", unit="u-1", prompt=PROMPT)
    assert (real / "work" / "j.requests.jsonl").is_file()
    assert client.record_to == (real / "work" / "j.requests.jsonl").resolve()


@pytest.mark.unit
def test_the_read_of_an_existing_file_does_not_follow_a_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The O_NOFOLLOW read holds even if a link slips past the path check."""
    target = tmp_path / "elsewhere.txt"
    target.write_text(json.dumps({"key": "a" * 64}) + "\n")
    link = tmp_path / "judge.requests.jsonl"
    link.symlink_to(target)
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    with pytest.raises(OSError):
        RecordReplayClient(MODEL, VERSION, record_to=link)


@pytest.mark.unit
async def test_a_folder_swapped_after_construction_does_not_redirect_writes(
    tmp_path: Path,
) -> None:
    folder = tmp_path / "work"
    folder.mkdir()
    client = RecordReplayClient(MODEL, VERSION, record_to=folder / "j.requests.jsonl")
    evil = tmp_path / "evil"
    evil.mkdir()
    folder.rename(tmp_path / "moved")
    folder.symlink_to(evil, target_is_directory=True)
    await client.complete(_user(TEXT), job="trace_judge", unit="u-1", prompt=PROMPT)
    assert list(evil.iterdir()) == []
    assert (tmp_path / "moved" / "j.requests.jsonl").is_file()


@pytest.mark.unit
async def test_a_hard_link_at_the_request_path_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.txt"
    target.write_text("")
    os.link(target, tmp_path / "j.requests.jsonl")
    with pytest.raises(ValueError, match="one link"):
        RecordReplayClient(MODEL, VERSION, record_to=tmp_path / "j.requests.jsonl")


@pytest.mark.unit
async def test_a_hard_link_made_after_construction_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "j.requests.jsonl"
    client = RecordReplayClient(MODEL, VERSION, record_to=out)
    target = tmp_path / "elsewhere.txt"
    target.write_text("keep\n")
    os.link(target, out)
    with pytest.raises(ValueError, match="one link"):
        await client.complete(_user(TEXT), job="trace_judge", unit="u-1", prompt=PROMPT)
    assert target.read_text() == "keep\n"


@pytest.mark.unit
def test_a_fifo_at_the_request_path_is_refused_without_blocking(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "j.requests.jsonl")
    with pytest.raises(ValueError, match="regular file"):
        RecordReplayClient(MODEL, VERSION, record_to=tmp_path / "j.requests.jsonl")


@pytest.mark.unit
async def test_a_link_planted_after_construction_is_not_followed(tmp_path: Path) -> None:
    out = tmp_path / "judge.requests.jsonl"
    client = RecordReplayClient(MODEL, VERSION, record_to=out)
    target = tmp_path / "elsewhere.txt"
    target.write_text("keep\n")
    out.symlink_to(target)
    with pytest.raises(OSError):
        await client.complete(_user(TEXT), job="trace_judge", unit="u-1", prompt=PROMPT)
    assert target.read_text() == "keep\n"


@pytest.mark.unit
async def test_a_new_request_file_is_owner_only(tmp_path: Path) -> None:
    out = tmp_path / "judge.requests.jsonl"
    client = RecordReplayClient(MODEL, VERSION, record_to=out)
    await client.complete(_user(TEXT), job="trace_judge", unit="u-1", prompt=PROMPT)
    assert out.stat().st_mode & 0o077 == 0


@pytest.mark.unit
def test_record_path_must_be_a_requests_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"\.requests\.jsonl"):
        RecordReplayClient(MODEL, VERSION, record_to=tmp_path / "judge.jsonl")


@pytest.mark.unit
@pytest.mark.parametrize(
    "kwargs",
    [{}, {"record_to": Path("a.requests.jsonl"), "replies": Path("outcomes.jsonl")}],
)
def test_exactly_one_mode(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="one of"):
        RecordReplayClient(MODEL, VERSION, **kwargs)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("messages", "unit"),
    [
        ([{"role": "system", "content": "s"}, {"role": "user", "content": TEXT}], "u-1"),
        ([{"role": "assistant", "content": TEXT}], "u-1"),
        ([], "u-1"),
        (_user("   "), "u-1"),
        (_user(TEXT), "has space"),
        (_user(TEXT), ""),
    ],
)
async def test_requests_the_sender_would_refuse_are_refused(
    tmp_path: Path, messages: list[dict[str, str]], unit: str
) -> None:
    out = tmp_path / "j.requests.jsonl"
    client = RecordReplayClient(MODEL, VERSION, record_to=out)
    with pytest.raises(ValueError):
        await client.complete(messages, job="trace_judge", unit=unit, prompt=PROMPT)
    assert not out.exists()


@pytest.mark.unit
async def test_complete_needs_job_unit_and_prompt(tmp_path: Path) -> None:
    client = RecordReplayClient(MODEL, VERSION, record_to=tmp_path / "j.requests.jsonl")
    with pytest.raises(TypeError):
        await client.complete(_user(TEXT))


# ── Replay ───────────────────────────────────────────────────────────


def _outcomes(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


@pytest.mark.unit
async def test_replay_returns_the_stored_fields_and_pending_otherwise(tmp_path: Path) -> None:
    key = request_key(PROMPT, MODEL, VERSION, TEXT)
    blocked = request_key(PROMPT, MODEL, VERSION, TEXT + "b")
    fields = {"verdict": "completed", "call": 0}
    replies = _outcomes(
        tmp_path / "outcomes.jsonl",
        [
            {"key": key, "unit": "u-1", "job": "trace_judge", "outcome": "reply", "fields": fields},
            {"key": blocked, "unit": "u-2", "job": "trace_judge", "outcome": "no_text"},
        ],
    )
    client = RecordReplayClient(MODEL, VERSION, replies=replies)
    got = await client.complete(_user(TEXT), job="trace_judge", unit="u-1", prompt=PROMPT)
    assert not isinstance(got, PendingResponse)
    assert json.loads(got.content) == fields and got.model == MODEL
    no_text = await client.complete(_user(TEXT + "b"), job="trace_judge", unit="u-2", prompt=PROMPT)
    assert isinstance(no_text, PendingResponse) and no_text.reason == "no_text"
    missing = await client.complete(_user(TEXT + "m"), job="trace_judge", unit="u-3", prompt=PROMPT)
    assert isinstance(missing, PendingResponse) and missing.reason == "missing"


# hybrid_send.CLASSES, copied: the sender's seven final outcome classes
CLASSES = (
    "reply",
    "unparsed",
    "no_text",
    "not_sent_oversize",
    "step_stopped",
    "no_reply_at_bound",
    "scan_hit",
)


@pytest.mark.unit
@pytest.mark.parametrize("outcome", CLASSES)
async def test_every_sender_outcome_class_loads_and_only_reply_is_a_reply(
    tmp_path: Path, outcome: str
) -> None:
    key = request_key(PROMPT, MODEL, VERSION, TEXT)
    fields = {"verdict": "none", "call": None} if outcome == "reply" else None
    row = {"key": key, "unit": "u-1", "job": "trace_judge", "outcome": outcome, "fields": fields}
    client = RecordReplayClient(
        MODEL, VERSION, replies=_outcomes(tmp_path / "outcomes.jsonl", [row])
    )
    got = await client.complete(_user(TEXT), job="trace_judge", unit="u-1", prompt=PROMPT)
    if outcome == "reply":
        assert not isinstance(got, PendingResponse) and json.loads(got.content) == fields
    else:
        assert isinstance(got, PendingResponse) and got.reason == outcome


@pytest.mark.unit
async def test_replay_under_another_model_misses(tmp_path: Path) -> None:
    key = request_key(PROMPT, MODEL, VERSION, TEXT)
    row = {"key": key, "unit": "u-1", "job": "trace_judge", "outcome": "reply", "fields": {}}
    replies = _outcomes(tmp_path / "outcomes.jsonl", [row])
    client = RecordReplayClient("other-model", VERSION, replies=replies)
    got = await client.complete(_user(TEXT), job="trace_judge", unit="u-1", prompt=PROMPT)
    assert isinstance(got, PendingResponse) and got.reason == "missing"


@pytest.mark.unit
@pytest.mark.parametrize(
    "body",
    [
        "not json\n",
        "[1]\n",
        json.dumps({"key": "k" * 64, "outcome": "reply", "fields": {}}) + "\n",
        json.dumps({"key": "a" * 64, "outcome": "reply", "fields": None}) + "\n",
        json.dumps({"key": "a" * 64, "outcome": "replied", "fields": {}}) + "\n",
        json.dumps({"key": "a" * 64, "outcome": ["reply"], "fields": {}}) + "\n",
        json.dumps({"key": "a" * 64, "outcome": "reply", "fields": {}}) * 1
        + "\n"
        + json.dumps({"key": "a" * 64, "outcome": "no_text"})
        + "\n",
    ],
)
def test_a_malformed_replies_file_is_refused_by_line_number(tmp_path: Path, body: str) -> None:
    path = tmp_path / "outcomes.jsonl"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match=r"line \d") as err:
        RecordReplayClient(MODEL, VERSION, replies=path)
    assert "not json" not in str(err.value)


@pytest.mark.unit
async def test_health_check_is_offline(tmp_path: Path) -> None:
    client = RecordReplayClient(MODEL, VERSION, record_to=tmp_path / "j.requests.jsonl")
    assert await client.health_check() is True


# ── No text reaches a log (promise 5) ────────────────────────────────


@pytest.mark.unit
async def test_no_request_or_reply_text_reaches_a_log(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    marker = "MARKER-7f3c-do-not-log"
    caplog.set_level(logging.DEBUG)
    text = f"{TEXT}{marker}\n"
    recorder = RecordReplayClient(MODEL, VERSION, record_to=tmp_path / "m.requests.jsonl")
    await recorder.complete(_user(text), job="trace_judge", unit="u-1", prompt=PROMPT)
    key = request_key(PROMPT, MODEL, VERSION, text)
    row = {"key": key, "unit": "u-1", "job": "trace_judge", "outcome": "reply"}
    replies = _outcomes(tmp_path / "outcomes.jsonl", [{**row, "fields": {"note": marker}}])
    replayer = RecordReplayClient(MODEL, VERSION, replies=replies)
    await replayer.complete(_user(text), job="trace_judge", unit="u-1", prompt=PROMPT)
    with pytest.raises(ValueError) as err:
        await recorder.complete(
            [{"role": "system", "content": marker}, *_user(text)],
            job="trace_judge",
            unit="u-1",
            prompt=PROMPT,
        )
    seen = capsys.readouterr()
    for where in (caplog.text, repr(caplog.records), seen.out, seen.err, str(err.value)):
        assert marker not in where
