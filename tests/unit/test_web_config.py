"""Tests for WebUIConfig."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from ziran.interfaces.web.config import WebUIConfig


@pytest.mark.unit
class TestWebUIConfig:
    def test_defaults(self) -> None:
        config = WebUIConfig()
        assert config.database_url == "postgresql+asyncpg://localhost:5432/ziran"
        assert config.host == "127.0.0.1"
        assert config.port == 8484
        assert config.dev_mode is False

    def test_from_env_defaults(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = WebUIConfig.from_env()
        assert config.database_url == "postgresql+asyncpg://localhost:5432/ziran"
        assert config.host == "127.0.0.1"
        assert config.port == 8484
        assert config.dev_mode is False

    def test_from_env_overrides(self) -> None:
        env = {
            "ZIRAN_DATABASE_URL": "postgresql+asyncpg://db:5432/test",
            "ZIRAN_HOST": "0.0.0.0",
            "ZIRAN_PORT": "9090",
            "ZIRAN_DEV_MODE": "true",
        }
        with patch.dict(os.environ, env, clear=True):
            config = WebUIConfig.from_env()
        assert config.database_url == "postgresql+asyncpg://db:5432/test"
        assert config.host == "0.0.0.0"
        assert config.port == 9090
        assert config.dev_mode is True

    def test_custom_values(self) -> None:
        config = WebUIConfig(
            database_url="postgresql+asyncpg://custom:5432/db",
            host="0.0.0.0",
            port=3000,
            dev_mode=True,
        )
        assert config.database_url == "postgresql+asyncpg://custom:5432/db"
        assert config.port == 3000
