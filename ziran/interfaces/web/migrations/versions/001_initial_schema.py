"""Initial schema — runs, phase_results, config_presets.

Revision ID: 001
Revises: None
Create Date: 2026-03-23
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

if TYPE_CHECKING:
    from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("target_agent", sa.String(500), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("coverage_level", sa.String(20), nullable=False, server_default="standard"),
        sa.Column("strategy", sa.String(20), nullable=False, server_default="fixed"),
        sa.Column("config_json", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("total_vulnerabilities", sa.Integer(), server_default="0"),
        sa.Column("critical_paths_count", sa.Integer(), server_default="0"),
        sa.Column("dangerous_chains_count", sa.Integer(), server_default="0"),
        sa.Column("final_trust_score", sa.Float(), nullable=True),
        sa.Column("total_tokens", sa.Integer(), server_default="0"),
        sa.Column("result_json", postgresql.JSONB(), nullable=True),
        sa.Column("graph_state_json", postgresql.JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_runs_status", "runs", ["status"])
    op.create_index("ix_runs_created_at", "runs", ["created_at"])

    op.create_table(
        "phase_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("phase", sa.String(50), nullable=False),
        sa.Column("phase_index", sa.Integer(), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("trust_score", sa.Float(), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=False),
        sa.Column("token_usage_json", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("vulnerabilities_found", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column(
            "discovered_capabilities", postgresql.JSONB(), nullable=False, server_default="[]"
        ),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_phase_results_run_id", "phase_results", ["run_id"])

    op.create_table(
        "config_presets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("config_json", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("config_presets")
    op.drop_table("phase_results")
    op.drop_table("runs")
