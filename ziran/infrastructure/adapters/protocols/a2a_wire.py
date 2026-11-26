"""HTTP implementation of the A2A identity-probe wire (spec 118).

Each request opens its own client, so a probe's clients share no connection or cookie. A client
other than ``target`` never carries the target's auth or headers. Requests go once: no retry, so
a failure reads unmeasured, never a pass.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from ziran.domain.interfaces.a2a_wire import A2AClient, A2AReply, A2AWire

if TYPE_CHECKING:
    from collections.abc import Callable

    from ziran.domain.entities.target import TargetConfig

_HISTORY = 50


class HttpA2AWire(A2AWire):
    """*build_client* makes an ``httpx.AsyncClient`` for a target config (auth, TLS, proxy)."""

    def __init__(
        self, config: TargetConfig, build_client: Callable[[TargetConfig], httpx.AsyncClient]
    ) -> None:
        super().__init__(config)
        self._build = build_client
        self._rpc_id = 0

    def _client(self, client: A2AClient) -> httpx.AsyncClient:
        if client == "target":
            return self._build(self.config)
        auth = {"peer": self.a2a.peer_auth, "replay": self.a2a.replay_auth}.get(client)
        return self._build(self.config.model_copy(update={"auth": auth, "headers": {}}))

    async def get(self, url: str, client: A2AClient = "anonymous") -> A2AReply:
        async with self._client(client) as http:
            try:
                return _reply(await http.get(url))
            except httpx.HTTPError as exc:
                return A2AReply(error=f"{type(exc).__name__}: {exc}")

    async def send(
        self, client: A2AClient, text: str, *, context_id: str, task_id: str | None = None
    ) -> A2AReply:
        message: dict[str, Any] = {
            "messageId": str(uuid.uuid4()),
            "role": "ROLE_USER",
            "parts": [{"text": text}],
            "contextId": context_id,
        }
        if task_id is not None:
            message["taskId"] = task_id
        params = {"message": message, "configuration": {"blocking": True}}
        return await self._call(client, "SendMessage", params, "/message:send")

    async def get_task(self, client: A2AClient, task_id: str) -> A2AReply:
        params = {"id": task_id, "historyLength": _HISTORY}
        return await self._call(client, "GetTask", params, f"/tasks/{quote(task_id, safe='')}")

    async def _call(
        self, client: A2AClient, method: str, params: dict[str, Any], path: str
    ) -> A2AReply:
        url = self.config.normalized_url
        headers = {"A2A-Version": self.a2a.a2a_version}
        rpc = self.a2a.protocol_binding == "JSONRPC"
        async with self._client(client) as http:
            try:
                if rpc:
                    self._rpc_id += 1
                    body = {"jsonrpc": "2.0", "id": self._rpc_id, "method": method}
                    response = await http.post(
                        url, json={**body, "params": params}, headers=headers
                    )
                elif method == "GetTask":
                    query = {"historyLength": _HISTORY}
                    response = await http.get(url + path, params=query, headers=headers)
                else:
                    response = await http.post(url + path, json=params, headers=headers)
            except httpx.HTTPError as exc:
                return A2AReply(error=f"{type(exc).__name__}: {exc}")
        reply = _reply(response)
        if rpc and reply.status == 200:
            error = reply.body.get("error")
            result = reply.body.get("result")
            if error is not None or not isinstance(result, dict):
                return reply.model_copy(update={"body": {}, "error": f"JSON-RPC error: {error}"})
            return reply.model_copy(update={"body": result})
        return reply


def _reply(response: httpx.Response) -> A2AReply:
    try:
        data = response.json()
    except ValueError:
        data = None
    body = data if isinstance(data, dict) else {}
    return A2AReply(status=response.status_code, body=body, text=response.text)
