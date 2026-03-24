"""Findings, compliance_mappings, export_jobs tables.

Revision ID: 002
Revises: 001
Create Date: 2026-03-24
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

if TYPE_CHECKING:
    from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("vector_id", sa.String(255), nullable=False),
        sa.Column("vector_name", sa.String(255), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("owasp_category", sa.String(10), nullable=True),
        sa.Column("target_agent", sa.String(255), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("prompt_used", sa.Text(), nullable=True),
        sa.Column("agent_response", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=True),
        sa.Column("detection_metadata", postgresql.JSONB(), nullable=True),
        sa.Column("business_impact", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_findings_severity",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'fixed', 'false_positive', 'ignored')",
            name="ck_findings_status",
        ),
    )
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index("ix_findings_run_id", "findings", ["run_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_owasp", "findings", ["owasp_category"])
    op.create_index("ix_findings_target", "findings", ["target_agent"])
    op.create_index("ix_findings_severity_status", "findings", ["severity", "status"])

    op.create_table(
        "compliance_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("framework", sa.String(50), nullable=False),
        sa.Column("control_id", sa.String(20), nullable=False),
        sa.Column("control_name", sa.String(255), nullable=False),
        sa.UniqueConstraint(
            "finding_id",
            "framework",
            "control_id",
            name="uq_compliance_finding_framework_control",
        ),
    )
    op.create_index("ix_compliance_finding", "compliance_mappings", ["finding_id"])
    op.create_index(
        "ix_compliance_framework_control",
        "compliance_mappings",
        ["framework", "control_id"],
    )

    op.create_table(
        "export_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("format", sa.String(10), nullable=False),
        sa.Column("filters_json", postgresql.JSONB(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("file_path", sa.String(500), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("export_jobs")
    op.drop_table("compliance_mappings")
    op.drop_table("findings")
