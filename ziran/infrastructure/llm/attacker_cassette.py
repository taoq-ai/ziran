"""Attacker cassette (spec 132): the attacker's replies as spec 064 outcome rows.

``Recorder`` passes each call to the real attacker client and keeps its reply; ``Cassette``
answers the same request from the file with no key and no socket, and a request with no stored
reply comes back pending, so the campaign stops the vector as unmeasured. The attacker request
is the system text plus the user text; the system text keys the reply as spec 064 defines. The
file never holds a key, the model id of the attacker is the only provider detail.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ziran.infrastructure.llm.base import BaseLLMClient, LLMResponse
from ziran.infrastructure.llm.replay_client import RecordReplayClient, _read_outcomes, request_key

if TYPE_CHECKING:
    from pathlib import Path

_VERSION = "v1"
_KEYED_AS = "attacker"  # the key does not name the model: a replay needs no attacker model


def _split(messages: list[dict[str, str]]) -> tuple[str, str]:
    if [m["role"] for m in messages] != ["system", "user"]:
        raise ValueError("an attacker request is one system and one user message")
    return messages[0]["content"], messages[1]["content"]


def _check_path(path: Path) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError(f"{path}: an attacker cassette path may not be a symlink")


class Recorder(BaseLLMClient):
    """Passes calls to *inner* and writes each reply to *path*, whole file, atomically."""

    def __init__(self, inner: BaseLLMClient, path: Path) -> None:
        super().__init__(inner.config)
        _check_path(path)
        self.inner, self.path = inner, path
        self._rows = _read_outcomes(path) if path.is_file() else {}

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> LLMResponse:
        system, user = _split(messages)
        reply = await self.inner.complete(messages, **kwargs)
        key = request_key(system, _KEYED_AS, _VERSION, user)
        row: dict[str, Any] = {"key": key, "unit": "campaign", "job": "campaign"}
        try:
            fields = json.loads(reply.content)
        except ValueError:
            fields = None
        if isinstance(fields, dict):
            row |= {"outcome": "reply", "fields": fields}
        else:
            row["outcome"] = "unparsed"  # replays as pending
        self._rows[key] = row | {"model": self.config.model}
        self._save()
        return reply

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            tmp.write_text("".join(json.dumps(r) + "\n" for r in self._rows.values()), "utf-8")
            tmp.chmod(0o600)
            tmp.replace(self.path)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    async def health_check(self) -> bool:
        return True


class Cassette(BaseLLMClient):
    """Replays *path*; reports the model the replies were recorded from."""

    def __init__(self, path: Path) -> None:
        _check_path(path)
        rows = _read_outcomes(path)
        model = next((str(r["model"]) for r in rows.values() if "model" in r), _KEYED_AS)
        self.inner = RecordReplayClient(_KEYED_AS, _VERSION, replies=path)
        super().__init__(self.inner.config.model_copy(update={"model": model}))

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> LLMResponse:
        system, user = _split(messages)
        return await self.inner.complete(
            [{"role": "user", "content": user}], job="campaign", unit="campaign", prompt=system
        )

    async def health_check(self) -> bool:
        return True
