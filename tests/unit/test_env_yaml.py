"""Unit tests for the !env / ${VAR} YAML loader."""

from __future__ import annotations

import pytest

from ziran.infrastructure.config.env_yaml import EnvVarError, load_yaml_with_env

pytestmark = pytest.mark.unit


def test_env_tag_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_HOOK", "https://hooks.example/abc")
    data = load_yaml_with_env("url: !env MY_HOOK\n")
    assert data["url"] == "https://hooks.example/abc"


def test_interpolation_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOK", "secret123")
    data = load_yaml_with_env("token: ${TOK}\n")
    assert data["token"] == "secret123"


def test_unset_env_raises() -> None:
    with pytest.raises(EnvVarError, match="ZIRAN_DOES_NOT_EXIST"):
        load_yaml_with_env("url: !env ZIRAN_DOES_NOT_EXIST\n")


def test_plain_values_unaffected() -> None:
    data = load_yaml_with_env("a: 1\nb: hello\n")
    assert data == {"a": 1, "b": "hello"}
