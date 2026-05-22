"""Unit tests for tool-schema confusion attack vectors.

Validates that the YAML vectors load correctly and conform to the
expected schema used by AttackLibrary.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_VECTOR_FILE = (
    Path(__file__).resolve().parents[2]
    / "ziran"
    / "application"
    / "attacks"
    / "vectors"
    / "tool_schema_confusion.yaml"
)

_REQUIRED_FIELDS = {
    "id",
    "name",
    "category",
    "target_phase",
    "severity",
    "description",
    "tags",
    "owasp_mapping",
    "prompts",
}

_REQUIRED_PROMPT_FIELDS = {
    "template",
    "success_indicators",
    "failure_indicators",
}


@pytest.fixture()
def vectors() -> list[dict[str, object]]:
    raw = yaml.safe_load(_VECTOR_FILE.read_text(encoding="utf-8"))
    assert "vectors" in raw
    return raw["vectors"]  # type: ignore[no-any-return]


@pytest.mark.unit
class TestToolSchemaVectorsLoad:
    """Verify YAML loads and parses without errors."""

    def test_file_exists(self) -> None:
        assert _VECTOR_FILE.exists()

    def test_valid_yaml(self) -> None:
        raw = yaml.safe_load(_VECTOR_FILE.read_text(encoding="utf-8"))
        assert isinstance(raw, dict)
        assert "vectors" in raw

    def test_has_vectors(self, vectors: list[dict[str, object]]) -> None:
        assert len(vectors) >= 8, f"Expected >= 8 vectors, got {len(vectors)}"


@pytest.mark.unit
class TestToolSchemaVectorsSchema:
    """Verify each vector conforms to expected schema."""

    def test_required_fields_present(self, vectors: list[dict[str, object]]) -> None:
        for v in vectors:
            missing = _REQUIRED_FIELDS - set(v.keys())
            assert not missing, f"Vector {v.get('id', '?')} missing fields: {missing}"

    def test_category_is_tool_manipulation(self, vectors: list[dict[str, object]]) -> None:
        for v in vectors:
            assert v["category"] == "tool_manipulation", (
                f"Vector {v['id']} has wrong category: {v['category']}"
            )

    def test_severity_is_valid(self, vectors: list[dict[str, object]]) -> None:
        valid = {"critical", "high", "medium", "low"}
        for v in vectors:
            assert v["severity"] in valid, f"Vector {v['id']} has invalid severity: {v['severity']}"

    def test_has_owasp_mapping(self, vectors: list[dict[str, object]]) -> None:
        for v in vectors:
            owasp = v["owasp_mapping"]
            assert isinstance(owasp, list) and len(owasp) > 0, (
                f"Vector {v['id']} missing OWASP mapping"
            )

    def test_prompts_have_required_fields(self, vectors: list[dict[str, object]]) -> None:
        for v in vectors:
            for i, prompt in enumerate(v["prompts"]):  # type: ignore[union-attr]
                missing = _REQUIRED_PROMPT_FIELDS - set(prompt.keys())
                assert not missing, f"Vector {v['id']} prompt {i} missing: {missing}"

    def test_has_schema_confusion_tags(self, vectors: list[dict[str, object]]) -> None:
        """At least one schema_confusion tag per vector."""
        confusion_tags = {
            "schema_confusion",
            "type_confusion",
            "enum_injection",
            "schema_override",
            "missing_fields",
            "extra_fields",
            "nested_payload",
        }
        for v in vectors:
            tags = set(v["tags"])  # type: ignore[arg-type]
            assert tags & confusion_tags, f"Vector {v['id']} has no schema confusion tag"

    def test_unique_ids(self, vectors: list[dict[str, object]]) -> None:
        ids = [v["id"] for v in vectors]
        assert len(ids) == len(set(ids)), "Duplicate vector IDs found"
