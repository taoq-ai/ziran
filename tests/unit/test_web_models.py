"""Tests for SQLAlchemy web UI models."""

from __future__ import annotations

import uuid

import pytest

from ziran.interfaces.web.models import Base, ConfigPreset, PhaseResultRow, Run


@pytest.mark.unit
class TestRunModel:
    def test_tablename(self) -> None:
        assert Run.__tablename__ == "runs"

    def test_fields_set(self) -> None:
        run = Run(
            target_agent="http://example.com/agent",
            status="running",
            coverage_level="comprehensive",
        )
        assert run.target_agent == "http://example.com/agent"
        assert run.status == "running"
        assert run.coverage_level == "comprehensive"

    def test_uuid_primary_key(self) -> None:
        run = Run(id=uuid.uuid4(), target_agent="test")
        assert isinstance(run.id, uuid.UUID)


@pytest.mark.unit
class TestPhaseResultRowModel:
    def test_tablename(self) -> None:
        assert PhaseResultRow.__tablename__ == "phase_results"

    def test_creation(self) -> None:
        row = PhaseResultRow(
            run_id=uuid.uuid4(),
            phase="reconnaissance",
            phase_index=0,
            success=True,
            trust_score=0.85,
            duration_seconds=12.5,
        )
        assert row.phase == "reconnaissance"
        assert row.trust_score == 0.85


@pytest.mark.unit
class TestConfigPresetModel:
    def test_tablename(self) -> None:
        assert ConfigPreset.__tablename__ == "config_presets"

    def test_creation(self) -> None:
        preset = ConfigPreset(name="quick-scan", config_json={"coverage": "essential"})
        assert preset.name == "quick-scan"


@pytest.mark.unit
class TestBaseMetadata:
    def test_all_tables_registered(self) -> None:
        table_names = set(Base.metadata.tables.keys())
        assert "runs" in table_names
        assert "phase_results" in table_names
        assert "config_presets" in table_names
