"""A2A identity probes against an in-process A2A server (spec 118)."""

from __future__ import annotations

import hashlib
import json
import sys
from typing import TYPE_CHECKING, Any

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import ec

from tests.a2a_servers import A2AServer, b64url, es256_jwk
from ziran.application.a2a_probe import missing_input, run_a2a_probe, runnable
from ziran.application.attacks.library import AttackLibrary
from ziran.domain.entities.target import A2AConfig, AuthConfig, AuthType, ProtocolType, TargetConfig
from ziran.infrastructure.adapters.http_adapter import HttpAgentAdapter

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.domain.entities.attack import AttackResult

pytestmark = pytest.mark.unit

PROBES = {
    "a2a_card_unsigned": "card_unsigned",
    "a2a_card_signature_invalid": "card_signature",
    "a2a_cross_client_context": "cross_client_context",
    "a2a_cross_client_task": "cross_client_task",
    "a2a_delegated_token_replay": "delegated_token_replay",
    "a2a_lookalike_card": "lookalike_card",
}
_LIB = AttackLibrary()


def _bearer(token: str) -> AuthConfig:
    return AuthConfig(type=AuthType.BEARER, token=token)


_A = {"auth": AuthConfig(type=AuthType.BEARER, token="tok-a")}
_AB = _A | {"peer_auth": AuthConfig(type=AuthType.BEARER, token="tok-b")}
_TOKENS = {"tok-a": "alice", "tok-b": "bob"}


async def _probe(vector_id: str, server: A2AServer, **config: Any) -> AttackResult:
    auth, headers = config.pop("auth", None), config.pop("headers", {})
    target = TargetConfig(
        url=server.url,
        protocol=ProtocolType.A2A,
        auth=auth,
        headers=headers,
        a2a=A2AConfig(**config),
    )
    vector = _LIB.get_vector(vector_id)
    assert vector is not None
    return await run_a2a_probe(vector, HttpAgentAdapter(target).a2a_wire)


def _unmeasured(result: AttackResult) -> bool:
    return not result.successful and result.evidence.get("outcome") == "unmeasured"


def _not_run(result: AttackResult, needs: str) -> bool:
    evidence = result.evidence
    return not result.successful and "outcome" not in evidence and needs in evidence["not_run"]


def _closed_url() -> str:
    with A2AServer() as server:
        return server.url


# -- the vectors ------------------------------------------------------------


def test_builtin_probe_vectors() -> None:
    for vector_id, probe in PROBES.items():
        v = _LIB.get_vector(vector_id)
        assert v is not None and v.a2a_probe == probe
        assert v.prompts == [] and v.protocol_filter == ["a2a"]
        assert v.atlas_mapping and v.owasp_agentic_mapping
    assert _LIB.get_vector("a2a_cross_client_context").severity == "high"  # type: ignore[union-attr]


def test_library_loads_a2a_probe_from_yaml(tmp_path: Path) -> None:
    base = {
        "name": "n",
        "category": "multi_agent",
        "target_phase": "reconnaissance",
        "severity": "high",
        "description": "d",
    }
    with_prompt = {**base, "id": "bad", "a2a_probe": "card_unsigned"}
    with_prompt["prompts"] = [{"template": "hi"}]
    vectors = [{**base, "id": "ok", "a2a_probe": "card_unsigned"}, with_prompt]
    vectors.append({**base, "id": "unknown", "a2a_probe": "card_magic"})
    (tmp_path / "v.yaml").write_text(yaml.safe_dump({"vectors": vectors}))
    lib = AttackLibrary(custom_dirs=[tmp_path], load_builtin=False)
    assert [v.id for v in lib.vectors] == ["ok"]
    assert lib.get_vector("ok").a2a_probe == "card_unsigned"  # type: ignore[union-attr]
    assert sorted(i for i, _ in lib.load_errors) == ["bad", "unknown"]


async def test_probe_on_a_target_without_a2a_does_not_run() -> None:
    vector = _LIB.get_vector("a2a_card_unsigned")
    assert vector is not None
    assert _not_run(await run_a2a_probe(vector, None), "an A2A target")


def test_runnable_leaves_out_probes_without_their_input() -> None:
    vectors = [_LIB.get_vector(v) for v in PROBES]
    target = TargetConfig(url="https://a.example", protocol=ProtocolType.A2A)
    wire = HttpAgentAdapter(target).a2a_wire
    warnings: list[str] = []
    kept = runnable(vectors, wire, warnings)
    assert [v.id for v in kept] == ["a2a_card_unsigned", "a2a_card_signature_invalid"]
    (warning,) = warnings
    assert "a2a_delegated_token_replay (set a2a.replay_auth)" in warning
    assert "a2a_cross_client_task (set a2a.peer_auth)" in warning
    assert runnable(vectors, wire, warnings) == kept and len(warnings) == 1  # one line
    assert runnable(vectors, None, warnings) == []


def test_oauth2_credentials_are_not_sent_so_the_probe_does_not_run() -> None:
    oauth = AuthConfig(type=AuthType.OAUTH2, client_id="c", token_url="https://t.example")
    assert "oauth2" in (missing_input("delegated_token_replay", A2AConfig(replay_auth=oauth)) or "")
    assert missing_input("card_unsigned", A2AConfig()) is None


# -- the card -----------------------------------------------------------------


async def test_unsigned_card_is_a_finding_with_its_sha256() -> None:
    with A2AServer() as server:
        result = await _probe("a2a_card_unsigned", server)
        signed = await _probe("a2a_card_signature_invalid", server)
    assert result.successful and result.severity == "high"
    assert result.evidence["card_sha256"] == hashlib.sha256(server.card_bytes).hexdigest()
    assert result.evidence["card_url"].endswith("/.well-known/agent-card.json")
    assert not signed.successful and signed.evidence["signatures"] == []


async def test_valid_signature_is_no_finding() -> None:
    with A2AServer(signed=True) as server:
        unsigned = await _probe("a2a_card_unsigned", server)
        result = await _probe("a2a_card_signature_invalid", server)
    assert not unsigned.successful and not _unmeasured(unsigned)
    assert not result.successful and not _unmeasured(result)
    assert result.evidence["signatures"][0]["result"] == "valid"
    assert result.evidence["signatures"][0]["key_source"] == "jku"


async def test_tampered_card_is_a_finding() -> None:
    with A2AServer(signed=True, tamper=True) as server:
        result = await _probe("a2a_card_signature_invalid", server)
    assert result.successful
    assert result.evidence["signatures"][0]["result"] == "invalid"


async def test_pinned_jwks_overrides_the_cards_jku() -> None:
    with A2AServer(signed=True) as server, A2AServer() as other:
        other.key = ec.generate_private_key(ec.SECP256R1())  # a key that did not sign the card
        result = await _probe(
            "a2a_card_signature_invalid", server, jwks_url=f"{other.url}/jwks.json"
        )
    assert result.successful
    assert result.evidence["signatures"][0]["key_source"] == "pinned"


@pytest.mark.parametrize(
    ("header", "verdict"),
    [
        ({"alg": "none", "kid": "k1"}, "alg not allowed: none"),
        ({"alg": "HS256", "kid": "k1"}, "alg not allowed: HS256"),
        ({"alg": "RS256", "kid": "k1"}, "invalid"),  # an EC key cannot check RS256
        ({"alg": "ES256", "kid": "other"}, "kid not in the JWKS: other"),
        ({"alg": ["ES256"], "kid": "k1"}, "alg not allowed: ['ES256']"),
        ({"alg": {"x": 1}, "kid": "k1"}, "alg not allowed: {'x': 1}"),
    ],
)
async def test_bad_signatures_are_findings(header: dict[str, Any], verdict: str) -> None:
    with A2AServer(signed=True, header=header) as server:
        result = await _probe(
            "a2a_card_signature_invalid", server, jwks_url=f"{server.url}/jwks.json"
        )
    assert result.successful
    assert result.evidence["signatures"][0]["result"] == verdict


_BLANK = {"protected": "", "signature": ""}


async def test_one_valid_signature_among_bad_ones_is_no_finding() -> None:
    with A2AServer(signed=True, extra_signatures=[_BLANK, _BLANK]) as server:
        result = await _probe("a2a_card_signature_invalid", server)
    assert not result.successful
    assert [c["result"] for c in result.evidence["signatures"]] == [
        "malformed protected header",
        "malformed protected header",
        "valid",
    ]


async def test_only_a_malformed_signature_is_a_finding() -> None:
    garbage = {"protected": b64url(b"not json"), "signature": "x"}
    with A2AServer(extra_signatures=[garbage]) as server:
        result = await _probe("a2a_card_signature_invalid", server)
        unsigned = await _probe("a2a_card_unsigned", server)
    assert result.successful and not unsigned.successful


@pytest.mark.parametrize("raw", [b"not json", b"[]", b"{}", b'{"name": 3}'])
async def test_unreadable_card_is_unmeasured(raw: bytes) -> None:
    with A2AServer(raw_card=raw) as server:
        result = await _probe("a2a_card_unsigned", server)
    assert _unmeasured(result) and "card" in result.evidence["error"]


async def test_foreign_jku_is_never_fetched_and_does_not_run() -> None:
    with A2AServer() as elsewhere:
        header = {"alg": "ES256", "kid": "k1", "jku": f"{elsewhere.url}/jwks.json"}
        with A2AServer(signed=True, header=header) as server:
            result = await _probe("a2a_card_signature_invalid", server)
    assert _not_run(result, "a2a.jwks_url")
    assert elsewhere.requests == []


def _no_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)


@pytest.mark.parametrize(
    "case",
    ["no cryptography", "malformed key", "unsupported key", "JWKS down", "JWKS redirect"],
)
async def test_a_signature_that_cannot_be_checked_is_unmeasured(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    jwks = {
        "malformed key": {"keys": [{"kty": "EC", "crv": "P-256", "x": "!!", "y": "", "kid": "k1"}]},
        "unsupported key": {"keys": [{"kty": "oct", "k": "c2VjcmV0", "kid": "k1"}]},
    }.get(case)
    if case == "no cryptography":
        _no_crypto(monkeypatch)
    with A2AServer(signed=True) as server, A2AServer(jwks=jwks) as keys:
        url = {"JWKS down": f"{_closed_url()}/jwks.json"}.get(case, f"{keys.url}/jwks.json")
        if case == "JWKS redirect":  # a redirect is never followed off the pinned URL
            url = f"{keys.url}/redirect"
        result = await _probe("a2a_card_signature_invalid", server, jwks_url=url)
    assert _unmeasured(result), result.evidence
    assert result.evidence["signatures"][0]["result"].startswith("unverifiable")


def test_es256_needs_a_p256_key() -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    from ziran.application.a2a_probe.jws import verify_card

    key = ec.generate_private_key(ec.SECP384R1())
    card = {"name": "Agent"}
    protected = b64url(json.dumps({"alg": "ES256", "kid": "k1"}).encode())
    payload = json.dumps(card, separators=(",", ":")).encode()
    signed = f"{protected}.{b64url(payload)}".encode()
    r, s = decode_dss_signature(key.sign(signed, ec.ECDSA(hashes.SHA256())))
    signature = b64url(r.to_bytes(48, "big") + s.to_bytes(48, "big"))
    numbers = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-384", "kid": "k1"}
    jwk |= {"x": b64url(numbers.x.to_bytes(48, "big")), "y": b64url(numbers.y.to_bytes(48, "big"))}
    assert not verify_card(card, "ES256", jwk, protected, signature)


async def test_card_fetch_failure_is_unmeasured() -> None:
    target = TargetConfig(url=_closed_url(), protocol=ProtocolType.A2A, timeout=2)
    vector = _LIB.get_vector("a2a_card_unsigned")
    assert vector is not None
    assert _unmeasured(await run_a2a_probe(vector, HttpAgentAdapter(target).a2a_wire))


def test_signature_checks_the_a2a_sdk_canonical_form() -> None:
    from ziran.application.a2a_probe.jws import verify_card

    key = ec.generate_private_key(ec.SECP256R1())
    card = {"name": "Agent", "description": "Café", "skills": [], "provider": {}}
    sdk_form = json.dumps(
        {"description": "Café", "name": "Agent"}, sort_keys=True, separators=(",", ":")
    )  # empties dropped, ASCII escapes
    protected = b64url(json.dumps({"alg": "ES256", "kid": "k1"}).encode())
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    signing_input = f"{protected}.{b64url(sdk_form.encode())}".encode()
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    signature = b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    assert verify_card(card, "ES256", es256_jwk(key), protected, signature)
    assert not verify_card({**card, "name": "Other"}, "ES256", es256_jwk(key), protected, signature)


# -- cross-client state -------------------------------------------------------


@pytest.mark.parametrize("binding", ["HTTP+JSON", "JSONRPC"])
async def test_cross_client_context_leak_carries_both_requests(binding: str) -> None:
    with A2AServer(vulnerable=True, tokens=_TOKENS) as server:
        result = await _probe("a2a_cross_client_context", server, protocol_binding=binding, **_AB)
    assert result.successful and result.severity == "high"
    a, b = result.evidence["requests"]
    canary = result.evidence["canary"]
    assert canary in a["text"] and canary not in b["text"]
    assert a["client"] == "target" and b["client"] == "peer"
    assert b["context_id"] == result.evidence["context_id"]
    assert any("history" in path for path in result.evidence["leaked_in"])
    sent = [r["authorization"] for r in server.requests if r["body"]]
    assert sent == ["Bearer tok-a", "Bearer tok-b"]


@pytest.mark.parametrize("binding", ["HTTP+JSON", "JSONRPC"])
async def test_isolated_contexts_are_no_finding(binding: str) -> None:
    with A2AServer(vulnerable=False, tokens=_TOKENS) as server:
        context = await _probe("a2a_cross_client_context", server, protocol_binding=binding, **_AB)
        task = await _probe("a2a_cross_client_task", server, protocol_binding=binding, **_AB)
    assert not context.successful and not _unmeasured(context)
    assert not task.successful and not _unmeasured(task)


async def test_cross_client_task_leak() -> None:
    with A2AServer(vulnerable=True, tokens=_TOKENS) as server:
        result = await _probe("a2a_cross_client_task", server, **_AB)
    assert result.successful
    assert result.evidence["task_id"] in server.tasks


@pytest.mark.parametrize("vector", ["a2a_cross_client_context", "a2a_cross_client_task"])
async def test_cross_client_without_a_second_credential_does_not_run(vector: str) -> None:
    with A2AServer(vulnerable=False) as server:  # no auth: A and B would be one principal
        result = await _probe(vector, server)
    assert _not_run(result, "a2a.peer_auth") and server.requests == []


@pytest.mark.parametrize("status", [401, 429, 500, 503])
@pytest.mark.parametrize("vector", ["a2a_cross_client_context", "a2a_cross_client_task"])
async def test_client_b_without_a_verdict_is_unmeasured(vector: str, status: int) -> None:
    with A2AServer(vulnerable=True, tokens=_TOKENS, fail={"tok-b": status}) as server:
        result = await _probe(vector, server, **_AB)
    assert _unmeasured(result) and result.evidence["b_status"] == status


async def test_client_a_refused_is_unmeasured() -> None:
    with A2AServer(vulnerable=True, tokens={"tok-b": "bob"}) as server:  # tok-a is unknown
        context = await _probe("a2a_cross_client_context", server, **_AB)
        task = await _probe("a2a_cross_client_task", server, **_AB)
    assert _unmeasured(context) and _unmeasured(task)


async def test_a_message_reply_gives_no_task_to_read() -> None:
    with A2AServer(vulnerable=True, tokens=_TOKENS, reply_message=True) as server:
        task = await _probe("a2a_cross_client_task", server, **_AB)
        context = await _probe("a2a_cross_client_context", server, **_AB)
    assert _unmeasured(task) and "no task" in task.evidence["error"]
    assert not _unmeasured(context)


async def test_each_plant_has_its_own_code() -> None:
    with A2AServer(vulnerable=True, tokens=_TOKENS) as server:
        one = await _probe("a2a_cross_client_context", server, **_AB)
        two = await _probe("a2a_cross_client_context", server, **_AB)
    assert one.evidence["canary"] != two.evidence["canary"]


# -- delegated token ----------------------------------------------------------


_OLD = {"tok-a": "alice"}


async def test_replayed_token_accepted_is_a_finding_without_the_token() -> None:
    replay = {"replay_auth": _bearer("tok-old")}
    with A2AServer(tokens=_OLD, revoked={"tok-old"}, vulnerable=True) as bad:
        result = await _probe("a2a_delegated_token_replay", bad, **_A, **replay)
    with A2AServer(tokens=_OLD, revoked={"tok-old"}, vulnerable=False) as good:
        refused = await _probe("a2a_delegated_token_replay", good, **_A, **replay)
    assert result.successful
    assert result.evidence["token_sha256"] == hashlib.sha256(b"tok-old").hexdigest()[:12]
    assert "tok-old" not in json.dumps(result.model_dump(mode="json"))
    assert [r["authorization"] for r in bad.requests] == ["Bearer tok-old"]
    assert not refused.successful and refused.evidence["status"] == 401
    assert not _unmeasured(refused)


@pytest.mark.parametrize("state", ["TASK_STATE_REJECTED", "TASK_STATE_AUTH_REQUIRED"])
async def test_replay_refused_in_the_task_state_is_no_finding(state: str) -> None:
    with A2AServer(tokens=_OLD, revoked={"tok-old"}, vulnerable=False, revoked_state=state) as s:
        result = await _probe("a2a_delegated_token_replay", s, **_A, replay_auth=_bearer("tok-old"))
    assert not result.successful and not _unmeasured(result)
    assert result.evidence["status"] == 200 and result.evidence["task_state"] == state


async def test_replay_refused_by_json_rpc_is_no_finding() -> None:
    with A2AServer(tokens=_OLD, revoked={"tok-old"}, vulnerable=False) as server:
        result = await _probe(
            "a2a_delegated_token_replay",
            server,
            protocol_binding="JSONRPC",
            replay_auth=_bearer("tok-old"),
            **_A,
        )
    assert not result.successful and not _unmeasured(result)
    assert result.evidence["error"] == "JSON-RPC error -32007"


@pytest.mark.parametrize("status", [429, 500, 503])
async def test_replay_without_a_verdict_is_unmeasured(status: int) -> None:
    with A2AServer(tokens=_OLD, revoked={"tok-old"}, fail={"tok-old": status}) as server:
        result = await _probe(
            "a2a_delegated_token_replay", server, **_A, replay_auth=_bearer("tok-old")
        )
    assert _unmeasured(result) and result.evidence["status"] == status


@pytest.mark.parametrize("token", ["tok-old\n", "tok-old\r\n"])
async def test_a_token_that_breaks_the_header_is_unmeasured_and_never_quoted(token: str) -> None:
    with A2AServer(tokens=_OLD, revoked={"tok-old"}) as server:
        result = await _probe("a2a_delegated_token_replay", server, replay_auth=_bearer(token))
        b = await _probe("a2a_cross_client_context", server, **_A, peer_auth=_bearer(token))
    for r in (result, b):
        assert _unmeasured(r)
        assert "tok-old" not in json.dumps(r.model_dump(mode="json"))


async def test_replay_without_a_recorded_token_does_not_run() -> None:
    with A2AServer() as server:
        result = await _probe("a2a_delegated_token_replay", server)
    assert _not_run(result, "a2a.replay_auth")


async def test_target_headers_reach_no_other_client() -> None:
    secret = {"headers": {"X-Api-Key": "HDRSECRET"}}
    with (
        A2AServer(vulnerable=True, tokens=_TOKENS, revoked={"tok-old"}, signed=True) as server,
        A2AServer(name="Trave1 Agent") as twin,
        A2AServer() as keys,
    ):
        cards = [f"{twin.url}/.well-known/agent-card.json"]
        jwks = f"{keys.url}/jwks.json"
        config = _AB | secret | {"lookalike_cards": cards, "jwks_url": jwks}
        for vector in PROBES:
            await _probe(vector, server, replay_auth=_bearer("tok-old"), **config)
    others = [r for r in server.requests if r["authorization"] != "Bearer tok-a"]
    target = [r for r in server.requests if r["authorization"] == "Bearer tok-a"]
    assert others and target and all("HDRSECRET" in json.dumps(r["headers"]) for r in target)
    for r in [*others, *twin.requests, *keys.requests]:
        assert "HDRSECRET" not in json.dumps(r["headers"]), r["path"]


# -- look-alike cards ---------------------------------------------------------


async def test_lookalike_card_on_another_origin_is_a_finding() -> None:
    with (
        A2AServer() as server,
        A2AServer(name="Trave1 Agent") as twin,
        A2AServer(name="Weather Bot") as other,
        A2AServer(skills=[{"id": "x", "name": "Other"}]) as unrelated,
    ):
        cards = [f"{s.url}/.well-known/agent-card.json" for s in (twin, other, unrelated)]
        result = await _probe("a2a_lookalike_card", server, **_A, lookalike_cards=cards)
    assert result.successful
    (hit,) = result.evidence["lookalikes"]
    assert hit["card_url"] == cards[0] and hit["shared_skills"] == ["book_trip"]
    assert hit["card_sha256"] == hashlib.sha256(twin.card_bytes).hexdigest()
    assert twin.requests[0]["authorization"] is None  # the target's token never leaves


async def test_lookalike_without_cards_does_not_run_and_without_answers_is_unmeasured() -> None:
    down = [f"{_closed_url()}/.well-known/agent-card.json"]
    with A2AServer() as server:
        none = await _probe("a2a_lookalike_card", server)
        unread = await _probe("a2a_lookalike_card", server, lookalike_cards=down)
    assert _not_run(none, "a2a.lookalike_cards")
    assert _unmeasured(unread)


async def test_the_targets_own_card_is_not_its_look_alike() -> None:
    with A2AServer() as server, A2AServer(name="Trave1 Agent") as twin:
        own = f"{server.url}/.well-known/agent-card.json"
        twin_card = f"{twin.url}/.well-known/agent-card.json"
        alone = await _probe("a2a_lookalike_card", server, lookalike_cards=[own, twin_card])
        assert [h["card_url"] for h in alone.evidence["lookalikes"]] == [twin_card]
        with A2AServer(name="Weather Bot") as other:
            card = f"{other.url}/.well-known/agent-card.json"
            clean = await _probe("a2a_lookalike_card", server, lookalike_cards=[own, card])
    assert not clean.successful and not _unmeasured(clean)
