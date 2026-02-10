"""Tests for the Skill CVE Database."""

from __future__ import annotations

import pytest

from koan.application.skill_cve import SkillCVE, SkillCVEDatabase
from koan.domain.entities.capability import AgentCapability, CapabilityType

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def db() -> SkillCVEDatabase:
    return SkillCVEDatabase()


@pytest.fixture
def langchain_capabilities() -> list[AgentCapability]:
    return [
        AgentCapability(
            id="cap-shell",
            name="ShellTool",
            type=CapabilityType.TOOL,
            dangerous=True,
            requires_permission=True,
        ),
        AgentCapability(
            id="cap-sqlite",
            name="SQLiteTool",
            type=CapabilityType.TOOL,
            dangerous=True,
            requires_permission=True,
        ),
        AgentCapability(
            id="cap-read",
            name="ReadFileTool",
            type=CapabilityType.TOOL,
            dangerous=False,
            requires_permission=False,
        ),
    ]


@pytest.fixture
def safe_capabilities() -> list[AgentCapability]:
    """Capabilities that should NOT match any known CVEs."""
    return [
        AgentCapability(
            id="cap-calc",
            name="Calculator",
            type=CapabilityType.TOOL,
            dangerous=False,
            requires_permission=False,
        ),
        AgentCapability(
            id="cap-weather",
            name="WeatherAPI",
            type=CapabilityType.EXTERNAL_API,
            dangerous=False,
            requires_permission=False,
        ),
    ]


# ── Tests: Database initialisation ───────────────────────────────────


class TestSkillCVEDatabaseInit:
    """Tests for database seeded state."""

    def test_seeds_are_loaded(self, db: SkillCVEDatabase) -> None:
        assert db.count >= 15

    def test_all_seeds_have_valid_fields(self, db: SkillCVEDatabase) -> None:
        for cve in db.all_cves:
            assert cve.cve_id.startswith("CVE-AGENT-")
            assert cve.skill_name
            assert cve.framework in ("langchain", "crewai", "mcp", "autogen", "generic")
            assert cve.severity in ("critical", "high", "medium", "low")
            assert cve.vulnerability_type
            assert cve.description
            assert cve.remediation

    def test_cve_ids_are_unique(self, db: SkillCVEDatabase) -> None:
        ids = [cve.cve_id for cve in db.all_cves]
        assert len(ids) == len(set(ids))


# ── Tests: check_agent() ─────────────────────────────────────────────


class TestCheckAgent:
    """Tests for matching agent capabilities against known CVEs."""

    def test_finds_matching_cves(
        self,
        db: SkillCVEDatabase,
        langchain_capabilities: list[AgentCapability],
    ) -> None:
        matches = db.check_agent(langchain_capabilities)
        assert len(matches) >= 1

        matched_skill_names = {m.skill_name for m in matches}
        # ShellTool should definitely match
        assert any("Shell" in name or "shell" in name for name in matched_skill_names)

    def test_safe_capabilities_no_matches(
        self,
        db: SkillCVEDatabase,
        safe_capabilities: list[AgentCapability],
    ) -> None:
        matches = db.check_agent(safe_capabilities)
        assert matches == []

    def test_empty_capabilities(self, db: SkillCVEDatabase) -> None:
        matches = db.check_agent([])
        assert matches == []

    def test_case_insensitive_matching(self, db: SkillCVEDatabase) -> None:
        """Tool names with different casing should still match."""
        caps = [
            AgentCapability(
                id="cap-1",
                name="SHELLTOOL",
                type=CapabilityType.TOOL,
                dangerous=True,
                requires_permission=True,
            ),
        ]
        matches = db.check_agent(caps)
        assert len(matches) >= 1


# ── Tests: get_by_id() ───────────────────────────────────────────────


class TestGetById:
    """Tests for lookup by CVE ID."""

    def test_existing_id(self, db: SkillCVEDatabase) -> None:
        cve = db.get_by_id("CVE-AGENT-2026-001")
        assert cve is not None
        assert cve.cve_id == "CVE-AGENT-2026-001"

    def test_missing_id(self, db: SkillCVEDatabase) -> None:
        cve = db.get_by_id("CVE-AGENT-9999-999")
        assert cve is None


# ── Tests: get_by_framework() ────────────────────────────────────────


class TestGetByFramework:
    """Tests for filtering by framework."""

    def test_langchain_has_entries(self, db: SkillCVEDatabase) -> None:
        results = db.get_by_framework("langchain")
        assert len(results) >= 5
        assert all(r.framework == "langchain" for r in results)

    def test_crewai_has_entries(self, db: SkillCVEDatabase) -> None:
        results = db.get_by_framework("crewai")
        assert len(results) >= 1
        assert all(r.framework == "crewai" for r in results)

    def test_unknown_framework_empty(self, db: SkillCVEDatabase) -> None:
        results = db.get_by_framework("nonexistent_framework")
        assert results == []


# ── Tests: get_by_severity() ─────────────────────────────────────────


class TestGetBySeverity:
    """Tests for filtering by severity."""

    def test_critical_has_entries(self, db: SkillCVEDatabase) -> None:
        results = db.get_by_severity("critical")
        assert len(results) >= 1
        assert all(r.severity == "critical" for r in results)

    def test_all_severities_represented(self, db: SkillCVEDatabase) -> None:
        """The seed data should cover critical, high, medium severities."""
        all_severities = {cve.severity for cve in db.all_cves}
        assert "critical" in all_severities
        assert "high" in all_severities
        assert "medium" in all_severities


# ── Tests: submit_cve() ──────────────────────────────────────────────


class TestSubmitCVE:
    """Tests for adding new CVEs."""

    def test_add_new_cve(self, db: SkillCVEDatabase) -> None:
        original_count = db.count
        new_cve = SkillCVE(
            cve_id="CVE-AGENT-2026-100",
            skill_name="DangerousTool",
            framework="generic",
            vulnerability_type="test_vuln",
            severity="low",
            description="A test vulnerability",
            remediation="Don't use it",
        )
        db.submit_cve(new_cve)
        assert db.count == original_count + 1
        assert db.get_by_id("CVE-AGENT-2026-100") is not None

    def test_duplicate_cve_rejected(self, db: SkillCVEDatabase) -> None:
        """Submitting a CVE with an existing ID should raise ValueError."""
        first_cve = db.all_cves[0]
        with pytest.raises(ValueError, match="already exists"):
            db.submit_cve(first_cve)

    def test_submitted_cve_retrievable(self, db: SkillCVEDatabase) -> None:
        new_cve = SkillCVE(
            cve_id="CVE-AGENT-2026-200",
            skill_name="TestSearch",
            framework="crewai",
            vulnerability_type="info_leak",
            severity="medium",
            description="Test",
            remediation="Fix",
        )
        db.submit_cve(new_cve)
        by_framework = db.get_by_framework("crewai")
        assert any(c.cve_id == "CVE-AGENT-2026-200" for c in by_framework)


# ── Tests: SkillCVE model ────────────────────────────────────────────


class TestSkillCVEModel:
    """Tests for the Pydantic model itself."""

    def test_valid_creation(self) -> None:
        cve = SkillCVE(
            cve_id="CVE-AGENT-2026-999",
            skill_name="TestTool",
            framework="generic",
            vulnerability_type="test",
            severity="low",
            description="desc",
            remediation="rem",
        )
        assert cve.cve_id == "CVE-AGENT-2026-999"

    def test_optional_fields_default(self) -> None:
        cve = SkillCVE(
            cve_id="CVE-AGENT-2026-998",
            skill_name="TestTool",
            framework="generic",
            vulnerability_type="test",
            severity="low",
            description="desc",
            remediation="rem",
        )
        assert cve.skill_version == "*"
        assert cve.references == []

    def test_serialization_roundtrip(self) -> None:
        cve = SkillCVE(
            cve_id="CVE-AGENT-2026-997",
            skill_name="RoundTrip",
            framework="langchain",
            vulnerability_type="rce",
            severity="critical",
            description="test roundtrip",
            remediation="fix it",
            skill_version="<=0.1.0",
            references=["https://example.com"],
        )
        data = cve.model_dump()
        restored = SkillCVE(**data)
        assert restored == cve

    def test_is_critical_property(self) -> None:
        cve_critical = SkillCVE(
            cve_id="CVE-AGENT-2026-996",
            skill_name="CriticalTool",
            framework="generic",
            vulnerability_type="rce",
            severity="critical",
            description="desc",
        )
        cve_low = SkillCVE(
            cve_id="CVE-AGENT-2026-995",
            skill_name="LowTool",
            framework="generic",
            vulnerability_type="info",
            severity="low",
            description="desc",
        )
        assert cve_critical.is_critical is True
        assert cve_low.is_critical is False
