"""Campaign id factory."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime


def new_campaign_id() -> str:
    """``campaign_<unix seconds>_<8 hex>``; the suffix keeps same-second scans apart."""
    return f"campaign_{int(datetime.now(tz=UTC).timestamp())}_{secrets.token_hex(4)}"
