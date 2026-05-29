"""YAML loading with environment-variable resolution.

Adds a ``!env VAR_NAME`` tag and ``${VAR}`` interpolation so secrets (webhook
URLs, tokens) can live in the environment instead of committed config files.
"""

from __future__ import annotations

import os
import re
from typing import Any

import yaml

_INTERPOLATE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class EnvVarError(ValueError):
    """Raised when a referenced environment variable is unset."""


class EnvSafeLoader(yaml.SafeLoader):
    """SafeLoader subclass scoped to this module (does not affect global yaml)."""


def _resolve(name: str) -> str:
    try:
        return os.environ[name]
    except KeyError as exc:
        raise EnvVarError(f"Environment variable '{name}' referenced in config is not set") from exc


def _env_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> str:
    """Resolve ``!env VAR_NAME`` to the value of ``$VAR_NAME``."""
    if not isinstance(node, yaml.ScalarNode):
        raise EnvVarError("!env requires a scalar variable name")
    name = str(loader.construct_scalar(node)).strip()
    return _resolve(name)


EnvSafeLoader.add_constructor("!env", _env_constructor)


def _interpolate(value: Any) -> Any:
    """Recursively expand ``${VAR}`` occurrences in all string values."""
    if isinstance(value, str):
        return _INTERPOLATE.sub(lambda m: _resolve(m.group(1)), value)
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    return value


def load_yaml_with_env(text: str) -> Any:
    """Parse YAML *text*, resolving ``!env VAR`` tags and ``${VAR}`` interpolation.

    Raises :class:`EnvVarError` if a referenced variable is unset.
    """
    return _interpolate(yaml.load(text, Loader=EnvSafeLoader))
