"""Load operator-supplied detector thresholds from ``.ziran/detectors.yaml``.

Thin adapter over :func:`load_yaml_with_env` that maps a YAML mapping onto
the :class:`DetectorThresholds` model. Keeping file I/O here (infrastructure)
preserves the hexagonal boundary — the application-layer pipeline stays free
of filesystem concerns.

Behaviour:
  * Missing file → documented defaults (``DetectorThresholds()``).
  * Empty file → defaults.
  * Partial mapping → provided keys override defaults; the rest default.
  * Invalid / out-of-range value, unknown key, or ``hit <= safe`` →
    :class:`DetectorConfigError` naming the offending field.

``!env VAR`` tags and ``${VAR}`` interpolation are supported via the shared
loader, for parity with other ZIRAN config files.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from ziran.application.detectors.thresholds import DetectorThresholds
from ziran.infrastructure.config.env_yaml import EnvVarError, load_yaml_with_env

#: Default location operators drop a threshold override into.
DEFAULT_CONFIG_PATH = Path(".ziran/detectors.yaml")


class DetectorConfigError(ValueError):
    """Raised when a detector config file is present but invalid."""


def load_detector_thresholds(
    path: str | Path | None = None,
) -> DetectorThresholds:
    """Load :class:`DetectorThresholds` from *path* (default ``.ziran/detectors.yaml``).

    Returns the documented defaults when the file is absent or empty.
    Raises :class:`DetectorConfigError` for malformed, unknown, or
    out-of-range values.
    """
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        return DetectorThresholds()

    text = config_path.read_text(encoding="utf-8")

    try:
        data = load_yaml_with_env(text)
    except EnvVarError as exc:
        raise DetectorConfigError(f"{config_path}: {exc}") from exc
    except Exception as exc:
        raise DetectorConfigError(f"{config_path}: invalid YAML — {exc}") from exc

    if data is None:
        return DetectorThresholds()

    if not isinstance(data, dict):
        raise DetectorConfigError(
            f"{config_path}: expected a mapping of threshold names to values, "
            f"got {type(data).__name__}"
        )

    try:
        return DetectorThresholds(**data)
    except ValidationError as exc:
        raise DetectorConfigError(f"{config_path}: {_format_validation_error(exc)}") from exc


def _format_validation_error(exc: ValidationError) -> str:
    """Render a Pydantic error into a concise, field-named message."""
    parts: list[str] = []
    for err in exc.errors():
        field = ".".join(str(loc) for loc in err["loc"]) or "<root>"
        parts.append(f"{field}: {err['msg']}")
    return "; ".join(parts)
