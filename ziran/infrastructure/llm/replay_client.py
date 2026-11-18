"""Record-and-replay model client for the hybrid detector (spec 064).

ziran never sends a hybrid model call. In record mode, ``complete()`` appends the rendered
request to a request file; ziran-paper's ``study/scripts/hybrid_send.py`` sends it through its
registered client and writes ``outcomes.jsonl``. In replay mode, ``complete()`` returns the
stored reply for the request's key. Either way, no socket or process is opened.

A request file holds rendered benchmark or user text, so it is written only to the path the
caller names, and no text is logged or put in an error message.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from typing import TYPE_CHECKING, Any

from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse, PendingResponse

if TYPE_CHECKING:
    from pathlib import Path

_UNIT = re.compile(r"[A-Za-z0-9_.:/#+-]{1,200}")  # hybrid_send.UNIT: the sender refuses others
_KEY = re.compile(r"[0-9a-f]{64}")
_SUFFIX = ".requests.jsonl"
# hybrid_send.CLASSES: the sender's final outcome classes
_OUTCOMES = frozenset(
    (
        "reply",
        "unparsed",
        "no_text",
        "not_sent_oversize",
        "step_stopped",
        "no_reply_at_bound",
        "scan_hit",
    )
)


def request_key(prompt: str, model: str, client_version: str, text: str, repeat: int = 0) -> str:
    """sha256 over the prompt file's text, the model id, the client version and the rendered
    text, each as an 8-byte big-endian length and its UTF-8 bytes, so no two tuples collide.
    A repeat send (protocol section 4) adds its index as a fifth part; repeat 0 adds none, so
    a first send's key is the four-part key ziran-paper#128 registers.

    Raises:
        ValueError: the repeat is not an int of 0 or more.
    """
    if type(repeat) is not int or repeat < 0:
        raise ValueError(f"a repeat index is an int of 0 or more, got {repeat!r}")
    h = hashlib.sha256()
    for part in (prompt, model, client_version, text, *([str(repeat)] if repeat else [])):
        data = part.encode("utf-8")
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


class RecordReplayClient(BaseLLMClient):
    """Writes requests (``record_to``) or reads stored replies (``replies``), one of the two.

    ``complete(messages, job=..., unit=..., prompt=..., repeat=0)`` takes one user message, the
    rendered text, the prompt file's text for the key, and the repeat index.
    """

    def __init__(
        self,
        model: str,
        client_version: str,
        *,
        record_to: Path | None = None,
        replies: Path | None = None,
    ) -> None:
        if (record_to is None) == (replies is None):
            raise ValueError("give one of record_to or replies")
        super().__init__(LLMConfig(provider="replay", model=model))
        self.client_version = client_version
        self.record_to = record_to
        self._seen: set[str] = set()
        self._replies: dict[str, dict[str, Any]] = {}
        self._dir: int | None = None
        if record_to is not None:
            if not record_to.name.endswith(_SUFFIX):
                raise ValueError(f"a request file's name ends in {_SUFFIX}")
            # CWE-59: the text must land at the named path, not where a planted link points.
            # The folder and the file may not be links; folders above it (macOS /tmp) are
            # resolved once here, and the folder is held open, so a folder swapped in later
            # cannot redirect the writes.
            if record_to.is_symlink() or record_to.parent.is_symlink():
                raise ValueError("a request file's path holds a symlink")
            self.record_to = record_to.parent.resolve() / record_to.name
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            self._dir = os.open(self.record_to.parent, flags)
            try:
                fd = self._open(os.O_RDONLY)
            except FileNotFoundError:
                pass
            else:
                with os.fdopen(fd, encoding="utf-8") as f:
                    self._seen = {json.loads(line)["key"] for line in _split(f.read())}
        if replies is not None:
            self._replies = _read_outcomes(replies)

    async def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        job, unit, prompt = (kwargs.get(k) for k in ("job", "unit", "prompt"))
        repeat = kwargs.get("repeat", 0)
        if not (isinstance(job, str) and isinstance(unit, str) and isinstance(prompt, str)):
            raise TypeError("complete() needs job=, unit= and prompt= strings")
        if len(messages) != 1 or set(messages[0]) != {"role", "content"}:
            raise ValueError("a hybrid request is one user message")
        if messages[0]["role"] != "user" or not messages[0]["content"].strip():
            raise ValueError("a hybrid request is one non-blank user message")
        if not _UNIT.fullmatch(unit):
            raise ValueError("the unit id is not one the sender accepts")
        text = messages[0]["content"]
        key = request_key(prompt, self.config.model, self.client_version, text, repeat)
        if self.record_to is not None:
            if key not in self._seen:
                row = {"key": key, "job": job, "unit": unit, "text": text}
                fd = self._open(os.O_APPEND | os.O_CREAT | os.O_WRONLY)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
                self._seen.add(key)
            return PendingResponse(model=self.config.model, reason="recorded")
        stored = self._replies.get(key)
        if stored is None:
            return PendingResponse(model=self.config.model, reason="missing")
        if stored["outcome"] != "reply":
            return PendingResponse(model=self.config.model, reason=stored["outcome"])
        return LLMResponse(content=json.dumps(stored["fields"]), model=self.config.model)

    async def health_check(self) -> bool:
        return True  # nothing to reach

    def _open(self, flags: int) -> int:
        """Open the request file in the held folder: no link (O_NOFOLLOW), no block on a FIFO
        (O_NONBLOCK), and only a regular file with one link, so no hard link is written through."""
        assert self._dir is not None and self.record_to is not None
        fd = os.open(
            self.record_to.name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self._dir
        )
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            os.close(fd)
            raise ValueError("a request file must be a regular file with one link")
        return fd

    def __del__(self) -> None:
        if getattr(self, "_dir", None) is not None:
            os.close(self._dir)  # type: ignore[arg-type]


def _split(text: str) -> list[str]:
    # "\n" only, as hybrid_send reads: a text may hold U+2028, which splitlines() would split on
    return [line for line in text.split("\n") if line.strip()]


def _read_outcomes(path: Path) -> dict[str, dict[str, Any]]:
    """hybrid_send's outcomes.jsonl: one {key, unit, job, outcome, fields} per final outcome."""
    rows: dict[str, dict[str, Any]] = {}
    for n, line in enumerate(_split(path.read_text(encoding="utf-8")), 1):
        try:
            row = json.loads(line)
        except ValueError:
            row = None
        ok = (
            isinstance(row, dict)
            and isinstance(row.get("key"), str)
            and _KEY.fullmatch(row["key"]) is not None
            and isinstance(row.get("outcome"), str)
            and row["outcome"] in _OUTCOMES
            and (row["outcome"] != "reply" or isinstance(row.get("fields"), dict))
        )
        if not ok:
            raise ValueError(f"{path.name} line {n} is not an outcome row")
        assert isinstance(row, dict)  # narrowed for mypy
        if row["key"] in rows:
            raise ValueError(f"{path.name} line {n} repeats a key")
        rows[row["key"]] = row
    return rows
