"""Unit tests for the attack-library web route handlers (spec 052, issue #368).

The library is a small stub monkeypatched into the route module, so the
assertions never depend on the bundled vector count.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ziran.domain.entities.attack import AttackPrompt, AttackVector
from ziran.interfaces.web.routes import library


def _vector(**overrides: Any) -> AttackVector:
    data: dict[str, Any] = {
        "id": "v",
        "name": "Vector",
        "category": "prompt_injection",
        "target_phase": "reconnaissance",
        "description": "A vector",
        "severity": "high",
        "prompts": [AttackPrompt(template="t")],
    }
    data.update(overrides)
    return AttackVector(**data)


VECTORS: list[AttackVector] = [
    _vector(
        id="v_alpha",
        name="Alpha Override",
        description="Overrides the system prompt",
        tags=["jailbreak"],
        owasp_mapping=["LLM01"],
        prompts=[AttackPrompt(template="alpha one"), AttackPrompt(template="alpha two")],
    ),
    _vector(
        id="v_beta",
        name="Beta Leak",
        category="data_exfiltration",
        severity="critical",
        target_phase="capability_mapping",
        description="Leaks SECRET tokens",
        tags=["exfil"],
        owasp_mapping=["LLM01", "LLM02"],
    ),
    _vector(
        id="v_gamma",
        name="Gamma Tool",
        category="tool_manipulation",
        description="Misuses a tool",
        tags=["Unicode-Smuggle"],
    ),
]


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    stub = SimpleNamespace(
        vectors=VECTORS,
        get_vector=lambda vid: next((v for v in VECTORS if v.id == vid), None),
    )
    monkeypatch.setattr(library, "get_attack_library", lambda: stub)
    app = FastAPI()
    app.include_router(library.router, prefix="/api/library")
    return TestClient(app)


def _ids(client: TestClient, params: dict[str, str]) -> list[str]:
    resp = client.get("/api/library/vectors", params=params)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == len(body["vectors"])
    return sorted(v["id"] for v in body["vectors"])


@pytest.mark.unit
class TestListVectors:
    def test_no_filter_returns_all(self, client: TestClient) -> None:
        assert _ids(client, {}) == ["v_alpha", "v_beta", "v_gamma"]

    @pytest.mark.parametrize(
        ("params", "expected"),
        [
            ({"category": "prompt_injection"}, ["v_alpha"]),
            ({"severity": "high"}, ["v_alpha", "v_gamma"]),
            ({"phase": "reconnaissance"}, ["v_alpha", "v_gamma"]),
            ({"owasp": "LLM01"}, ["v_alpha", "v_beta"]),
            ({"owasp": "LLM02"}, ["v_beta"]),
        ],
    )
    def test_single_filter(
        self, client: TestClient, params: dict[str, str], expected: list[str]
    ) -> None:
        assert _ids(client, params) == expected

    @pytest.mark.parametrize(
        ("term", "expected"),
        [
            ("alpha", ["v_alpha"]),  # name
            ("secret", ["v_beta"]),  # description, case differs
            ("unicode", ["v_gamma"]),  # tag, case differs
            ("ALPHA", ["v_alpha"]),  # upper-case term
        ],
    )
    def test_search_is_case_insensitive(
        self, client: TestClient, term: str, expected: list[str]
    ) -> None:
        assert _ids(client, {"search": term}) == expected

    @pytest.mark.parametrize(
        ("params", "expected"),
        [
            ({"category": "prompt_injection", "severity": "high"}, ["v_alpha"]),
            ({"severity": "high", "search": "tool"}, ["v_gamma"]),
        ],
    )
    def test_combined_filters(
        self, client: TestClient, params: dict[str, str], expected: list[str]
    ) -> None:
        assert _ids(client, params) == expected

    def test_no_match_returns_empty(self, client: TestClient) -> None:
        resp = client.get("/api/library/vectors", params={"category": "model_dos"})
        assert resp.status_code == 200
        assert resp.json() == {"vectors": [], "total": 0}

    def test_summary_shape(self, client: TestClient) -> None:
        items = client.get("/api/library/vectors").json()["vectors"]
        beta = next(v for v in items if v["id"] == "v_beta")
        assert beta["owasp_mapping"] == ["LLM01", "LLM02"]
        assert beta["prompt_count"] == 1
        assert beta["target_phase"] == "capability_mapping"


@pytest.mark.unit
class TestGetVector:
    def test_found_returns_prompts(self, client: TestClient) -> None:
        resp = client.get("/api/library/vectors/v_alpha")
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == "v_alpha"
        assert [p["template"] for p in body["prompts"]] == ["alpha one", "alpha two"]

    def test_unknown_is_404(self, client: TestClient) -> None:
        resp = client.get("/api/library/vectors/nope")
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Vector not found"}


@pytest.mark.unit
class TestLibraryStats:
    def test_aggregates(self, client: TestClient) -> None:
        resp = client.get("/api/library/stats")
        assert resp.status_code == 200
        assert resp.json() == {
            "total_vectors": 3,
            "total_prompts": 4,
            "by_category": {
                "prompt_injection": 1,
                "data_exfiltration": 1,
                "tool_manipulation": 1,
            },
            "by_severity": {"high": 2, "critical": 1},
            "by_owasp": {"LLM01": 2, "LLM02": 1},
        }
