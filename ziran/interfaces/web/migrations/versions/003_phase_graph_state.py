"""Add per-phase knowledge-graph snapshot to phase_results.

Revision ID: 003
Revises: 002
Create Date: 2026-06-22
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

if TYPE_CHECKING:
    from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Nullable so existing rows (pre spec-026) remain valid; the UI scrubber
    # falls back to the run's final graph_state_json when this is NULL.
    op.add_column(
        "phase_results",
        sa.Column("graph_state_json", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("phase_results", "graph_state_json")
