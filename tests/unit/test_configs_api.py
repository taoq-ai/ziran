"""Unit tests for the config-preset web route handlers (spec 052, issue #368).

``get_db`` is overridden with a mocked ``AsyncSession``; no database, no
lifespan (which would run Alembic against PostgreSQL).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ziran.interfaces.web.dependencies import get_db
from ziran.interfaces.web.models import ConfigPreset
from ziran.interfaces.web.routes import configs

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

T0 = datetime(2026, 1, 1, tzinfo=UTC)
RESPONSE_KEYS = {"id", "name", "description", "config_json", "created_at", "updated_at"}


def _preset(name: str = "baseline", **overrides: Any) -> ConfigPreset:
    data: dict[str, Any] = {
        "id": uuid.uuid4(),
        "name": name,
        "description": "desc",
        "config_json": {"a": 1},
        "created_at": T0,
        "updated_at": T0,
    }
    data.update(overrides)
    return ConfigPreset(**data)


async def _fill_server_defaults(obj: ConfigPreset) -> None:
    """Emulate the column defaults a real flush would apply."""
    if obj.id is None:
        obj.id = uuid.uuid4()
    if obj.created_at is None:
        obj.created_at = T0
    if obj.updated_at is None:
        obj.updated_at = T0


@pytest.fixture
def db() -> MagicMock:
    session = MagicMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=result)
    session.get = AsyncMock(return_value=None)
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.delete = AsyncMock()
    session.refresh = AsyncMock(side_effect=_fill_server_defaults)
    return session


@pytest.fixture
def client(db: MagicMock) -> TestClient:
    app = FastAPI()
    app.include_router(configs.router, prefix="/api")

    async def _override() -> AsyncGenerator[MagicMock, None]:
        yield db

    app.dependency_overrides[get_db] = _override
    return TestClient(app)


@pytest.mark.unit
class TestListConfigs:
    def test_lists_presets(self, client: TestClient, db: MagicMock) -> None:
        presets = [_preset("one"), _preset("two")]
        db.execute.return_value.scalars.return_value.all.return_value = presets
        resp = client.get("/api/configs")
        assert resp.status_code == 200
        body = resp.json()
        assert [p["name"] for p in body] == ["one", "two"]
        assert [p["id"] for p in body] == [str(p.id) for p in presets]
        assert all(set(p) == RESPONSE_KEYS for p in body)


@pytest.mark.unit
class TestCreateConfig:
    def test_created(self, client: TestClient, db: MagicMock) -> None:
        resp = client.post(
            "/api/configs", json={"name": "n", "description": "d", "config": {"k": 1}}
        )
        assert resp.status_code == 201
        body = resp.json()
        assert (body["name"], body["description"], body["config_json"]) == ("n", "d", {"k": 1})
        db.add.assert_called_once()
        added = db.add.call_args.args[0]
        assert isinstance(added, ConfigPreset)
        assert added.config_json == {"k": 1}
        db.commit.assert_awaited_once()
        db.refresh.assert_awaited_once()

    def test_duplicate_name_is_409(self, client: TestClient, db: MagicMock) -> None:
        db.execute.return_value.scalar_one_or_none.return_value = _preset("n")
        resp = client.post("/api/configs", json={"name": "n", "config": {}})
        assert resp.status_code == 409
        assert resp.json() == {"detail": "Config preset name already exists"}
        db.add.assert_not_called()
        db.commit.assert_not_awaited()

    def test_missing_name_is_422(self, client: TestClient, db: MagicMock) -> None:
        resp = client.post("/api/configs", json={"config": {}})
        assert resp.status_code == 422
        db.execute.assert_not_awaited()


@pytest.mark.unit
class TestUpdateConfig:
    def test_config_maps_to_config_json(self, client: TestClient, db: MagicMock) -> None:
        preset = _preset()
        db.get.return_value = preset
        resp = client.put(f"/api/configs/{preset.id}", json={"config": {"z": 2}})
        assert resp.status_code == 200
        body = resp.json()
        assert body["config_json"] == {"z": 2}
        assert (body["name"], body["description"]) == ("baseline", "desc")
        assert datetime.fromisoformat(body["updated_at"]) > T0
        db.commit.assert_awaited_once()
        db.get.assert_awaited_once_with(ConfigPreset, preset.id)

    def test_name_and_description_only(self, client: TestClient, db: MagicMock) -> None:
        preset = _preset()
        db.get.return_value = preset
        resp = client.put(
            f"/api/configs/{preset.id}", json={"name": "renamed", "description": "new"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert (body["name"], body["description"]) == ("renamed", "new")
        assert body["config_json"] == {"a": 1}

    def test_missing_is_404(self, client: TestClient, db: MagicMock) -> None:
        resp = client.put(f"/api/configs/{uuid.uuid4()}", json={"name": "x"})
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Config preset not found"}
        db.commit.assert_not_awaited()

    def test_non_uuid_is_422(self, client: TestClient, db: MagicMock) -> None:
        resp = client.put("/api/configs/not-a-uuid", json={"name": "x"})
        assert resp.status_code == 422
        db.get.assert_not_awaited()


@pytest.mark.unit
class TestDeleteConfig:
    def test_deleted(self, client: TestClient, db: MagicMock) -> None:
        preset = _preset()
        db.get.return_value = preset
        resp = client.delete(f"/api/configs/{preset.id}")
        assert resp.status_code == 204
        assert resp.content == b""
        db.delete.assert_awaited_once_with(preset)
        db.commit.assert_awaited_once()

    def test_missing_is_404(self, client: TestClient, db: MagicMock) -> None:
        resp = client.delete(f"/api/configs/{uuid.uuid4()}")
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Config preset not found"}
        db.delete.assert_not_awaited()

    def test_non_uuid_is_422(self, client: TestClient, db: MagicMock) -> None:
        resp = client.delete("/api/configs/not-a-uuid")
        assert resp.status_code == 422
        db.get.assert_not_awaited()
