"""An in-process A2A server on 127.0.0.1 for the identity probes (spec 118).

``vulnerable=True`` keys contexts and tasks by id alone, so any client reads another's history,
and it accepts revoked tokens. ``vulnerable=False`` binds each context and task to the client
that made it and rejects revoked tokens. The card can be unsigned, signed (ES256, ``jku`` on this
server) or signed and then tampered with.
"""

from __future__ import annotations

import base64
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

CARD_PATH = "/.well-known/agent-card.json"
SKILLS = [{"id": "book_trip", "name": "Book trip", "description": "Books flights and hotels"}]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def es256_jwk(key: ec.EllipticCurvePrivateKey, kid: str = "k1") -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    x, y = (n.to_bytes(32, "big") for n in (numbers.x, numbers.y))
    return {"kty": "EC", "crv": "P-256", "x": b64url(x), "y": b64url(y), "kid": kid}


def sign_card(
    card: dict[str, Any], key: ec.EllipticCurvePrivateKey, header: dict[str, Any]
) -> dict:
    """The A2A 1.0 signature: JWS over the RFC 8785 card without ``signatures``."""
    payload = json.dumps(card, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    protected = b64url(json.dumps(header).encode())
    signing_input = f"{protected}.{b64url(payload.encode())}".encode()
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return {
        "protected": protected,
        "signature": b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
    }


class A2AServer:
    """Use as a context manager; ``url`` is set while it runs."""

    def __init__(
        self,
        *,
        vulnerable: bool = True,
        signed: bool = False,
        tamper: bool = False,
        header: dict[str, Any] | None = None,
        extra_signatures: list[dict[str, str]] | None = None,
        raw_card: bytes | None = None,
        tokens: dict[str, str] | None = None,
        revoked: set[str] | None = None,
        name: str = "Travel Agent",
        skills: list[dict[str, str]] | None = None,
        fail: dict[str, int] | None = None,
        reply_message: bool = False,
        revoked_state: str | None = None,
        jwks: dict[str, Any] | None = None,
    ) -> None:
        self.vulnerable, self.signed, self.tamper, self.header = vulnerable, signed, tamper, header
        self.extra_signatures, self.raw_card = extra_signatures or [], raw_card
        self.tokens = tokens or {}  # bearer token -> client; empty means the server has no auth
        self.revoked = revoked or set()
        self.name, self.skills = name, SKILLS if skills is None else skills
        self.fail = fail or {}  # bearer token -> HTTP status for every A2A call it makes
        self.reply_message = reply_message  # answer with a message, not a task
        self.revoked_state = revoked_state  # refuse a revoked token with HTTP 200 and this state
        self.jwks = jwks
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.contexts: dict[str, tuple[str, list[dict[str, Any]]]] = {}
        self.tasks: dict[str, tuple[str, dict[str, Any]]] = {}
        self.requests: list[dict[str, Any]] = []
        self.url = ""
        self.card_bytes = b""

    # -- the card ---------------------------------------------------------

    def _card(self) -> dict[str, Any]:
        card: dict[str, Any] = {
            "name": self.name,
            "description": "Plans trips",
            "version": "1.0.0",
            "supportedInterfaces": [{"url": self.url, "protocolBinding": "HTTP+JSON"}],
            "skills": self.skills,
        }
        if self.signed:
            header = self.header or {"alg": "ES256", "kid": "k1", "jku": f"{self.url}/jwks.json"}
            card["signatures"] = [sign_card(card, self.key, header)]
        if self.extra_signatures:  # listed before the real one
            card["signatures"] = self.extra_signatures + card.get("signatures", [])
        if self.tamper:
            card["description"] = "Plans trips and moves money"
        return card

    # -- A2A methods ------------------------------------------------------

    def _client(self, headers: Any) -> str | None:
        """The calling client, or None when the token is refused."""
        if not self.tokens:
            return "anonymous"
        token = (headers.get("Authorization") or "").removeprefix("Bearer ")
        if token in self.revoked:
            return "revoked" if self.vulnerable or self.revoked_state else None
        return self.tokens.get(token)

    def send_message(self, client: str, params: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        message = params["message"]
        context_id = message.get("contextId") or str(uuid.uuid4())
        owner, history = self.contexts.setdefault(context_id, (client, []))
        if owner != client and not self.vulnerable:  # a foreign context starts a new one
            context_id = str(uuid.uuid4())
            owner, history = self.contexts.setdefault(context_id, (client, []))
        reply = {"role": "ROLE_AGENT", "parts": [{"text": "Noted."}], "contextId": context_id}
        history += [message, reply]
        if self.reply_message:
            return 200, {"message": reply}
        task = {
            "id": str(uuid.uuid4()),
            "contextId": context_id,
            "status": {"state": "TASK_STATE_COMPLETED"},
            "history": list(history),
            "artifacts": [{"artifactId": "a1", "parts": [{"text": "Noted."}]}],
        }
        if client == "revoked" and self.revoked_state:
            task["status"] = {"state": self.revoked_state}
        self.tasks[task["id"]] = (client, task)
        return 200, {"task": task}

    def get_task(self, client: str, task_id: str) -> tuple[int, dict[str, Any]]:
        owner, task = self.tasks.get(task_id, ("", {}))
        if not task or (owner != client and not self.vulnerable):
            return 404, {"error": "task not found"}
        return 200, task

    # -- HTTP -------------------------------------------------------------

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, status: int, body: dict[str, Any] | bytes) -> None:
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _record(self, body: Any = None) -> str | None:
                auth = self.headers.get("Authorization")
                record = {"path": self.path, "authorization": auth, "body": body}
                server.requests.append(record | {"headers": dict(self.headers)})
                return server._client(self.headers)

            def _failed(self) -> bool:
                token = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
                if token in server.fail:
                    self._send(server.fail[token], {"error": "unavailable"})
                return token in server.fail

            def do_GET(self) -> None:
                client = self._record()
                if self.path == CARD_PATH:
                    return self._send(200, server.card_bytes)
                if self.path == "/jwks.json":
                    return self._send(200, server.jwks or {"keys": [es256_jwk(server.key)]})
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/jwks.json")
                    self.send_header("Content-Length", "0")
                    return self.end_headers()
                if self._failed():
                    return None
                if client is None:
                    return self._send(401, {"error": "unauthorized"})
                if self.path.startswith("/tasks/"):
                    task_id = self.path.removeprefix("/tasks/").split("?")[0]
                    return self._send(*server.get_task(client, task_id))
                self._send(404, {"error": "not found"})

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                client = self._record(body)
                if self._failed():
                    return None
                if client is None and self.path == "/":  # JSON-RPC refuses in the body
                    error = {"code": -32007, "message": "Unauthenticated"}
                    return self._send(200, {"jsonrpc": "2.0", "id": body["id"], "error": error})
                if client is None:
                    return self._send(401, {"error": "unauthorized"})
                if self.path == "/message:send":
                    return self._send(*server.send_message(client, body))
                if self.path == "/":  # JSON-RPC binding
                    params, rid = body["params"], body["id"]
                    if body["method"] == "SendMessage":
                        status, result = server.send_message(client, params)
                    else:
                        status, result = server.get_task(client, params["id"])
                    if status != 200:
                        error = {"code": -32001, "message": "Task not found"}
                        return self._send(200, {"jsonrpc": "2.0", "id": rid, "error": error})
                    return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": result})
                self._send(404, {"error": "not found"})

        return Handler

    def __enter__(self) -> A2AServer:
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{self._http.server_address[1]}"
        self.card_bytes = self.raw_card or json.dumps(self._card()).encode()
        self._thread = threading.Thread(target=self._http.serve_forever, args=(0.01,), daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._http.shutdown()
        self._http.server_close()
        self._thread.join()
