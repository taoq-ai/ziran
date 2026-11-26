"""JWS check of an A2A Agent Card signature (spec 118).

A2A 1.0 signs the RFC 8785 (JCS) form of the card without ``signatures`` as an RFC 7515 JWS
with a detached payload. ``cryptography`` (declared in the ``a2a`` extra) is imported only
here, when a card carries a signature.
"""

from __future__ import annotations

import base64
import json
from typing import Any

ALGORITHMS = frozenset({"ES256", "ES384", "RS256", "EdDSA"})


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _drop_empty(value: Any) -> Any:
    """The a2a-sdk signer's form: empty strings, lists and objects removed, recursively."""
    if isinstance(value, dict):
        kept = {k: c for k, v in value.items() if (c := _drop_empty(v)) is not None}
        return kept or None
    if isinstance(value, list):
        items = [c for v in value if (c := _drop_empty(v)) is not None]
        return items or None
    return None if value == "" else value


def canonical_forms(card: dict[str, Any]) -> list[bytes]:
    """RFC 8785 of the card as served, then without empty values, then the a2a-sdk signer's
    form (no empty values, ASCII escapes). Keys sort as RFC 8785 says for ASCII keys."""
    body = {k: v for k, v in card.items() if k != "signatures"}
    lean = _drop_empty(body) or {}
    forms = [
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        json.dumps(lean, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        json.dumps(lean, sort_keys=True, separators=(",", ":")),
    ]
    return [f.encode() for f in dict.fromkeys(forms)]


def verify_card(
    card: dict[str, Any], alg: str, jwk: dict[str, Any], protected: str, signature: str
) -> bool:
    """True when *signature* verifies over a canonical form of *card* with the key *jwk*.

    A key whose type does not fit *alg* (algorithm confusion) is False. Raises ``ValueError``
    for a malformed key and ``ImportError`` without ``cryptography``.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    key = _public_key(jwk)
    raw = b64decode(signature)
    for payload in canonical_forms(card):
        signed = f"{protected}.{_b64encode(payload)}".encode()
        try:
            curve = {"ES256": "secp256r1", "ES384": "secp384r1"}.get(alg)  # RFC 7518 3.4
            if isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == curve:
                half = len(raw) // 2
                der = encode_dss_signature(
                    int.from_bytes(raw[:half], "big"), int.from_bytes(raw[half:], "big")
                )
                digest = hashes.SHA256() if alg == "ES256" else hashes.SHA384()
                key.verify(der, signed, ec.ECDSA(digest))
            elif alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
                key.verify(raw, signed, padding.PKCS1v15(), hashes.SHA256())
            elif alg == "EdDSA" and isinstance(key, ed25519.Ed25519PublicKey):
                key.verify(raw, signed)
            else:
                return False
        except InvalidSignature:
            continue
        return True
    return False


def _public_key(jwk: dict[str, Any]) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    def number(name: str) -> int:
        return int.from_bytes(b64decode(str(jwk[name])), "big")

    try:
        kty, crv = jwk.get("kty"), jwk.get("crv")
        if kty == "EC" and crv in ("P-256", "P-384"):
            curve = ec.SECP256R1() if crv == "P-256" else ec.SECP384R1()
            return ec.EllipticCurvePublicNumbers(number("x"), number("y"), curve).public_key()
        if kty == "RSA":
            return rsa.RSAPublicNumbers(number("e"), number("n")).public_key()
        if kty == "OKP" and crv == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(b64decode(str(jwk["x"])))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"malformed JWK: {exc}") from None
    raise ValueError(f"unsupported JWK: kty={kty} crv={crv}")
