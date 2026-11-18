"""Tests for the Skill CVE Database."""

from __future__ import annotations

import pytest

from ziran.application.skill_cve import SkillCVE, SkillCVEDatabase
from ziran.domain.entities.capability import AgentCapability, CapabilityType

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
            assert cve.cve_id.startswith(("CVE-", "DESIGN-RISK-"))
            assert cve.skill_name
            assert cve.framework in ("langchain", "crewai", "mcp", "autogen", "generic")
            assert cve.severity in ("critical", "high", "medium", "low")
            assert cve.vulnerability_type
            assert cve.description
            assert cve.remediation
            assert cve.risk_type in ("cve", "design_risk")

    def test_cve_ids_are_unique(self, db: SkillCVEDatabase) -> None:
        ids = [cve.cve_id for cve in db.all_cves]
        assert len(ids) == len(set(ids))

    def test_real_cves_have_references(self, db: SkillCVEDatabase) -> None:
        """Real CVEs should have at least one reference URL."""
        for cve in db.all_cves:
            if cve.risk_type == "cve":
                assert len(cve.references) >= 1, f"{cve.cve_id} missing references"


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
                id="shell_execute",
                name="Shell Execute",
                type=CapabilityType.TOOL,
                description="Executes arbitrary shell commands",
                dangerous=True,
                requires_permission=True,
            ),
        ]
        matches = db.check_agent(caps)
        assert len(matches) >= 1
        # Should match DESIGN-RISK-001 (ShellTool) via keyword overlap
        assert any(m.cve_id == "DESIGN-RISK-001" for m in matches)


# ── Tests: get_by_id() ───────────────────────────────────────────────


class TestGetById:
    """Tests for lookup by CVE ID."""

    def test_existing_real_cve(self, db: SkillCVEDatabase) -> None:
        cve = db.get_by_id("CVE-2023-46229")
        assert cve is not None
        assert cve.cve_id == "CVE-2023-46229"
        assert cve.risk_type == "cve"

    def test_existing_design_risk(self, db: SkillCVEDatabase) -> None:
        cve = db.get_by_id("DESIGN-RISK-001")
        assert cve is not None
        assert cve.cve_id == "DESIGN-RISK-001"
        assert cve.risk_type == "design_risk"

    def test_missing_id(self, db: SkillCVEDatabase) -> None:
        cve = db.get_by_id("CVE-9999-99999")
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

    def test_mcp_has_entries(self, db: SkillCVEDatabase) -> None:
        results = db.get_by_framework("mcp")
        assert len(results) >= 1
        assert all(r.framework == "mcp" for r in results)

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


# ── Tests: get_by_risk_type() ────────────────────────────────────────


class TestGetByRiskType:
    """Tests for filtering by risk type."""

    def test_has_real_cves(self, db: SkillCVEDatabase) -> None:
        results = db.get_by_risk_type("cve")
        assert len(results) >= 5
        assert all(r.risk_type == "cve" for r in results)

    def test_has_design_risks(self, db: SkillCVEDatabase) -> None:
        results = db.get_by_risk_type("design_risk")
        assert len(results) >= 5
        assert all(r.risk_type == "design_risk" for r in results)


# ── Tests: submit_cve() ──────────────────────────────────────────────


class TestSubmitCVE:
    """Tests for adding new CVEs."""

    def test_add_new_cve(self, db: SkillCVEDatabase) -> None:
        original_count = db.count
        new_cve = SkillCVE(
            cve_id="CVE-2099-99999",
            skill_name="DangerousTool",
            framework="generic",
            vulnerability_type="test_vuln",
            severity="low",
            description="A test vulnerability",
            remediation="Don't use it",
            risk_type="cve",
        )
        db.submit_cve(new_cve)
        assert db.count == original_count + 1
        assert db.get_by_id("CVE-2099-99999") is not None

    def test_duplicate_cve_rejected(self, db: SkillCVEDatabase) -> None:
        """Submitting a CVE with an existing ID should raise ValueError."""
        first_cve = db.all_cves[0]
        with pytest.raises(ValueError, match="already exists"):
            db.submit_cve(first_cve)

    def test_submitted_cve_retrievable(self, db: SkillCVEDatabase) -> None:
        new_cve = SkillCVE(
            cve_id="DESIGN-RISK-999",
            skill_name="TestSearch",
            framework="crewai",
            vulnerability_type="info_leak",
            severity="medium",
            description="Test",
            remediation="Fix",
            risk_type="design_risk",
        )
        db.submit_cve(new_cve)
        by_framework = db.get_by_framework("crewai")
        assert any(c.cve_id == "DESIGN-RISK-999" for c in by_framework)


# ── Tests: SkillCVE model ────────────────────────────────────────────


class TestSkillCVEModel:
    """Tests for the Pydantic model itself."""

    def test_valid_creation(self) -> None:
        cve = SkillCVE(
            cve_id="CVE-2099-99998",
            skill_name="TestTool",
            framework="generic",
            vulnerability_type="test",
            severity="low",
            description="desc",
            remediation="rem",
        )
        assert cve.cve_id == "CVE-2099-99998"

    def test_optional_fields_default(self) -> None:
        cve = SkillCVE(
            cve_id="CVE-2099-99997",
            skill_name="TestTool",
            framework="generic",
            vulnerability_type="test",
            severity="low",
            description="desc",
            remediation="rem",
        )
        assert cve.skill_version == "*"
        assert cve.references == []
        assert cve.risk_type == "cve"
        assert cve.cvss_score is None

    def test_serialization_roundtrip(self) -> None:
        cve = SkillCVE(
            cve_id="CVE-2099-99996",
            skill_name="RoundTrip",
            framework="langchain",
            vulnerability_type="rce",
            severity="critical",
            description="test roundtrip",
            remediation="fix it",
            skill_version="<=0.1.0",
            references=["https://example.com"],
            risk_type="cve",
            cvss_score=9.8,
        )
        data = cve.model_dump()
        restored = SkillCVE(**data)
        assert restored == cve

    def test_is_critical_property(self) -> None:
        cve_critical = SkillCVE(
            cve_id="CVE-2099-99995",
            skill_name="CriticalTool",
            framework="generic",
            vulnerability_type="rce",
            severity="critical",
            description="desc",
        )
        cve_low = SkillCVE(
            cve_id="CVE-2099-99994",
            skill_name="LowTool",
            framework="generic",
            vulnerability_type="info",
            severity="low",
            description="desc",
        )
        assert cve_critical.is_critical is True
        assert cve_low.is_critical is False


# ──────────────────────────────────────────────────────────────────────
# Agent and MCP advisories published 2026-03-20 to 2026-11-18 (spec 075)
# ──────────────────────────────────────────────────────────────────────

BATCH_2026H2 = [
    "CVE-2026-77260",
    "CVE-2026-77248",
    "CVE-2026-77262",
    "CVE-2026-77253",
    "CVE-2026-77246",
    "CVE-2026-73498",
    "CVE-2026-77255",
    "CVE-2026-116686",
    "CVE-2026-104850",
    "CVE-2026-32871",
    "CVE-2026-105697",
    "CVE-2025-61260",
    "CVE-2026-54316",
    "CVE-2026-39861",
    "CVE-2026-88968",
    "CVE-2026-55607",
    "CVE-2026-40068",
    "CVE-2026-113663",
    "CVE-2026-7700",
    "CVE-2026-59207",
    "CVE-2026-65015",
    "CVE-2026-86996",
]

# Types the ground truth already uses (skill CVE entries, run.py guardrail map, scenarios).
KNOWN_TYPES = {
    "command_injection",
    "credential_theft",
    "data_exfiltration",
    "path_traversal",
    "privilege_escalation",
    "prompt_injection",
    "remote_code_execution",
    "ssrf",
    "symlink_bypass",
}


def _cap(tool_id: str, description: str) -> AgentCapability:
    return AgentCapability(
        id=tool_id, name=tool_id, type=CapabilityType.TOOL, description=description
    )


@pytest.mark.unit
class TestBatch2026H2:
    @pytest.mark.parametrize("cve_id", BATCH_2026H2)
    def test_entry_is_complete(self, db: SkillCVEDatabase, cve_id: str) -> None:
        cve = db.get_by_id(cve_id)
        assert cve is not None, cve_id
        assert cve.risk_type == "cve"
        assert cve.references[0].startswith("https://github.com/advisories/GHSA-")
        assert f"https://nvd.nist.gov/vuln/detail/{cve_id}" in cve.references
        assert cve.skill_version != "*"
        assert cve.vulnerability_type in KNOWN_TYPES
        assert cve.discovered_date is not None
        assert cve.discovered_date.date().isoformat() >= "2026-03-20"

    def test_upload_attachment_matches_its_cves(self, db: SkillCVEDatabase) -> None:
        cap = _cap(
            "confluence_upload_attachment",
            "mcp-atlassian tool: opens a server-local file_path and uploads it.",
        )
        found = {c.cve_id for c in db.check_agent([cap])}
        assert {"CVE-2026-77260", "CVE-2026-77262", "CVE-2026-73498"} <= found

    def test_read_only_jira_tool_matches_nothing_new(self, db: SkillCVEDatabase) -> None:
        cap = _cap("jira_search", "Searches Jira issues with JQL in read-only mode.")
        found = {c.cve_id for c in db.check_agent([cap])}
        assert not found & set(BATCH_2026H2)

    def test_huggingface_preapproval_matches_only_when_named(self, db: SkillCVEDatabase) -> None:
        open_fetch = _cap("WebFetch", "Claude Code WebFetch with huggingface.co pre-approved.")
        scoped = _cap("WebFetch", "Fetches pages from docs.python.org only.")
        assert "CVE-2026-54316" in {c.cve_id for c in db.check_agent([open_fetch])}
        assert not {c.cve_id for c in db.check_agent([scoped])} & set(BATCH_2026H2)


# ──────────────────────────────────────────────────────────────────────
# Re-export module (database.py)
# ──────────────────────────────────────────────────────────────────────


class TestDatabaseReExport:
    def test_imports(self) -> None:
        from ziran.application.skill_cve.database import SkillCVE, SkillCVEDatabase

        assert SkillCVE is not None
        assert SkillCVEDatabase is not None
