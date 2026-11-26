"""A2A identity probes against an in-process A2A server (spec 118)."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import ec

from tests.a2a_servers import A2AServer, b64url, es256_jwk
from ziran.application.a2a_probe import run_a2a_probe
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


async def _probe(vector_id: str, server: A2AServer, **config: Any) -> AttackResult:
    auth = config.pop("auth", None)
    target = TargetConfig(
        url=server.url, protocol=ProtocolType.A2A, auth=auth, a2a=A2AConfig(**config)
    )
    vector = _LIB.get_vector(vector_id)
    assert vector is not None
    return await run_a2a_probe(vector, HttpAgentAdapter(target).a2a_wire)


def _unmeasured(result: AttackResult) -> bool:
    return not result.successful and result.evidence.get("outcome") == "unmeasured"


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


async def test_probe_on_a_target_without_a2a_is_unmeasured() -> None:
    vector = _LIB.get_vector("a2a_card_unsigned")
    assert vector is not None
    assert _unmeasured(await run_a2a_probe(vector, None))


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
    ],
)
async def test_bad_signatures_are_findings(header: dict[str, str], verdict: str) -> None:
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


async def test_foreign_jku_is_never_fetched_and_is_unmeasured() -> None:
    with A2AServer() as elsewhere:
        header = {"alg": "ES256", "kid": "k1", "jku": f"{elsewhere.url}/jwks.json"}
        with A2AServer(signed=True, header=header) as server:
            result = await _probe("a2a_card_signature_invalid", server)
    assert _unmeasured(result)
    assert elsewhere.requests == []


async def test_card_fetch_failure_is_unmeasured() -> None:
    with A2AServer() as server:
        url = server.url
    target = TargetConfig(url=url, protocol=ProtocolType.A2A, timeout=2)
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
    with A2AServer(vulnerable=True) as server:
        result = await _probe("a2a_cross_client_context", server, protocol_binding=binding)
    assert result.successful and result.severity == "high"
    a, b = result.evidence["requests"]
    canary = result.evidence["canary"]
    assert canary in a["text"] and canary not in b["text"]
    assert a["client"] == "target" and b["client"] == "anonymous"
    assert b["context_id"] == result.evidence["context_id"]
    assert any("history" in path for path in result.evidence["leaked_in"])


async def test_isolated_contexts_are_no_finding() -> None:
    clients = {"auth": _bearer("tok-a"), "peer_auth": _bearer("tok-b")}
    with A2AServer(vulnerable=False, tokens={"tok-a": "alice", "tok-b": "bob"}) as server:
        context = await _probe("a2a_cross_client_context", server, **clients)
        task = await _probe("a2a_cross_client_task", server, **clients)
    assert not context.successful and not _unmeasured(context)
    assert not task.successful and not _unmeasured(task)
    assert task.evidence["b_status"] == 404


async def test_cross_client_task_leak() -> None:
    with A2AServer(vulnerable=True) as server:
        result = await _probe("a2a_cross_client_task", server)
    assert result.successful
    assert result.evidence["task_id"] in server.tasks


async def test_cross_client_on_an_authenticated_target_needs_a_peer() -> None:
    tokens = {"tok-a": "alice", "tok-b": "bob"}
    with A2AServer(tokens=tokens) as server:
        missing = await _probe("a2a_cross_client_context", server, auth=_bearer("tok-a"))
        server.requests.clear()
        found = await _probe(
            "a2a_cross_client_context", server, auth=_bearer("tok-a"), peer_auth=_bearer("tok-b")
        )
    assert _unmeasured(missing) and "peer_auth" in missing.evidence["skipped"]
    assert found.successful
    sent = [r["authorization"] for r in server.requests if r["body"]]
    assert sent == ["Bearer tok-a", "Bearer tok-b"]


# -- delegated token ----------------------------------------------------------


async def test_replayed_token_accepted_is_a_finding_without_the_token() -> None:
    tokens = {"tok-a": "alice"}
    with A2AServer(tokens=tokens, revoked={"tok-old"}, vulnerable=True) as bad:
        result = await _probe(
            "a2a_delegated_token_replay", bad, auth=_bearer("tok-a"), replay_auth=_bearer("tok-old")
        )
    with A2AServer(tokens=tokens, revoked={"tok-old"}, vulnerable=False) as good:
        refused = await _probe(
            "a2a_delegated_token_replay",
            good,
            auth=_bearer("tok-a"),
            replay_auth=_bearer("tok-old"),
        )
    assert result.successful
    assert result.evidence["token_sha256"] == hashlib.sha256(b"tok-old").hexdigest()[:12]
    assert "tok-old" not in json.dumps(result.model_dump(mode="json"))
    assert [r["authorization"] for r in bad.requests] == ["Bearer tok-old"]
    assert not refused.successful and refused.evidence["status"] == 401


async def test_replay_without_a_recorded_token_is_unmeasured() -> None:
    with A2AServer() as server:
        result = await _probe("a2a_delegated_token_replay", server)
    assert _unmeasured(result) and "replay_auth" in result.evidence["skipped"]


# -- look-alike cards ---------------------------------------------------------


async def test_lookalike_card_on_another_origin_is_a_finding() -> None:
    with (
        A2AServer() as server,
        A2AServer(name="Trave1 Agent") as twin,
        A2AServer(name="Weather Bot") as other,
        A2AServer(skills=[{"id": "x", "name": "Other"}]) as unrelated,
    ):
        cards = [f"{s.url}/.well-known/agent-card.json" for s in (twin, other, unrelated)]
        result = await _probe(
            "a2a_lookalike_card", server, auth=_bearer("tok-a"), lookalike_cards=cards
        )
    assert result.successful
    (hit,) = result.evidence["lookalikes"]
    assert hit["card_url"] == cards[0] and hit["shared_skills"] == ["book_trip"]
    assert hit["card_sha256"] == hashlib.sha256(twin.card_bytes).hexdigest()
    assert twin.requests[0]["authorization"] is None  # the target's token never leaves


async def test_lookalike_without_cards_or_answers_is_unmeasured() -> None:
    with A2AServer() as server:
        none = await _probe("a2a_lookalike_card", server)
        down = await _probe("a2a_lookalike_card", server, lookalike_cards=["http://127.0.0.1:9/c"])
    assert _unmeasured(none) and "lookalike_cards" in none.evidence["skipped"]
    assert _unmeasured(down)
