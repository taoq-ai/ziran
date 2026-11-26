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
_MAX_BYTES = 1 << 20


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
        # another client is another principal: none of the target's auth, headers or client cert
        auth = {"peer": self.a2a.peer_auth, "replay": self.a2a.replay_auth}.get(client)
        tls = self.config.tls.model_copy(update={"client_cert": None, "client_key": None})
        return self._build(self.config.model_copy(update={"auth": auth, "headers": {}, "tls": tls}))

    async def _request(self, client: A2AClient, method: str, url: str, **kwargs: Any) -> A2AReply:
        try:
            async with self._client(client) as http:
                # only the target's own requests follow redirects, so a JWKS or a look-alike
                # card cannot send ziran to another host
                kwargs.setdefault("follow_redirects", client == "target")
                response = await http.request(method, url, **kwargs)
        except (httpx.HTTPError, ValueError) as exc:  # the type only: a message can quote a token
            return A2AReply(error=type(exc).__name__)
        return _reply(response)

    async def get(self, url: str, client: A2AClient = "anonymous") -> A2AReply:
        return await self._request(client, "GET", url)

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
        if rpc:
            self._rpc_id += 1
            body = {"jsonrpc": "2.0", "id": self._rpc_id, "method": method, "params": params}
            reply = await self._request(client, "POST", url, json=body, headers=headers)
        elif method == "GetTask":
            query = {"historyLength": _HISTORY}
            reply = await self._request(client, "GET", url + path, params=query, headers=headers)
        else:
            reply = await self._request(client, "POST", url + path, json=params, headers=headers)
        if rpc and reply.status == 200:
            error = reply.body.get("error")
            result = reply.body.get("result")
            if error is not None or not isinstance(result, dict):
                code = error.get("code") if isinstance(error, dict) else None
                # an int code only: a server's text can quote the credential it refused
                label = f"JSON-RPC error {code}" if type(code) is int else "JSON-RPC error"
                return reply.model_copy(update={"body": {}, "error": label})
            return reply.model_copy(update={"body": result})
        return reply


def _reply(response: httpx.Response) -> A2AReply:
    # ponytail: the cap is checked after the read, so it bounds parsing, not memory; stream
    # the body if a hostile target sending gigabytes matters
    if len(response.content) > _MAX_BYTES:
        return A2AReply(status=response.status_code, error=f"response over {_MAX_BYTES} bytes")
    try:
        data = response.json()
    except RecursionError:  # nested too deep to read: no usable answer, as if none came
        return A2AReply(status=0, error="reply nested too deep")
    except ValueError:
        data = None
    body = data if isinstance(data, dict) else {}
    return A2AReply(status=response.status_code, body=body, text=response.text)
