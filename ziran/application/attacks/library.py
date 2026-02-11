"""Attack library — loads and manages attack vectors from YAML files.

The attack library provides a registry of all available attack vectors,
loaded from YAML files in the built-in vectors directory and optionally
from user-specified custom directories.

YAML Schema:
    ```yaml
    vectors:
      - id: unique_identifier
        name: Human-Readable Name
        category: prompt_injection  # See AttackCategory enum
        target_phase: reconnaissance  # See ScanPhase enum
        severity: high  # low, medium, high, critical
        description: What this attack does
        tags: [tag1, tag2]
        references: [https://...]
        prompts:
          - template: "Prompt with {variable} placeholders"
            variables:
              variable: "default value"
            success_indicators: ["pattern1", "pattern2"]
            failure_indicators: ["block1", "block2"]
    ```
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from ziran.domain.entities.attack import (
    AttackCategory,
    AttackPrompt,
    AttackVector,
    OwaspLlmCategory,
    Severity,
)
from ziran.domain.entities.phase import CoverageLevel, ScanPhase

logger = logging.getLogger(__name__)

# Severity tiers used by coverage levels
_COVERAGE_SEVERITIES: dict[CoverageLevel, set[Severity]] = {
    CoverageLevel.ESSENTIAL: {"critical"},
    CoverageLevel.STANDARD: {"critical", "high"},
    CoverageLevel.COMPREHENSIVE: {"critical", "high", "medium", "low"},
}

# Built-in vectors directory (relative to this file)
_BUILTIN_VECTORS_DIR = Path(__file__).parent / "vectors"


class AttackLibraryError(Exception):
    """Raised when the attack library encounters an error."""


class AttackLibrary:
    """Registry of attack vectors loaded from YAML files.

    Loads vectors from the built-in directory and optionally from
    additional custom directories. Provides filtering by phase,
    category, severity, and tags.

    Example:
        ```python
        library = AttackLibrary()
        recon_attacks = library.get_attacks_for_phase(ScanPhase.RECONNAISSANCE)
        critical = library.get_attacks_by_severity("critical")
        ```
    """

    def __init__(
        self,
        custom_dirs: list[Path] | None = None,
        load_builtin: bool = True,
    ) -> None:
        """Initialize the attack library.

        Args:
            custom_dirs: Additional directories to load YAML vectors from.
            load_builtin: Whether to load the built-in vector library.
        """
        self._vectors: dict[str, AttackVector] = {}

        if load_builtin:
            self._load_directory(_BUILTIN_VECTORS_DIR)

        for custom_dir in custom_dirs or []:
            self._load_directory(custom_dir)

        logger.info(
            "Attack library initialized with %d vectors from %d categories",
            len(self._vectors),
            len(self.categories),
        )

    @property
    def vectors(self) -> list[AttackVector]:
        """All loaded attack vectors."""
        return list(self._vectors.values())

    @property
    def vector_count(self) -> int:
        """Total number of loaded vectors."""
        return len(self._vectors)

    @property
    def categories(self) -> set[AttackCategory]:
        """All categories represented in the library."""
        return {v.category for v in self._vectors.values()}

    def get_vector(self, vector_id: str) -> AttackVector | None:
        """Get a specific vector by ID.

        Args:
            vector_id: The unique vector identifier.

        Returns:
            The vector if found, None otherwise.
        """
        return self._vectors.get(vector_id)

    def get_attacks_for_phase(
        self,
        phase: ScanPhase,
        coverage: CoverageLevel = CoverageLevel.COMPREHENSIVE,
    ) -> list[AttackVector]:
        """Get attack vectors targeting a specific phase, filtered by coverage level.

        Args:
            phase: The scan phase to filter by.
            coverage: Coverage level controlling which severity tiers are included.

        Returns:
            List of vectors targeting this phase within the coverage tier.
        """
        allowed = _COVERAGE_SEVERITIES[coverage]
        return [
            v for v in self._vectors.values() if v.target_phase == phase and v.severity in allowed
        ]

    def get_attacks_by_category(self, category: AttackCategory) -> list[AttackVector]:
        """Get all attack vectors in a specific category.

        Args:
            category: The attack category to filter by.

        Returns:
            List of vectors in this category.
        """
        return [v for v in self._vectors.values() if v.category == category]

    def get_attacks_by_severity(self, severity: Severity) -> list[AttackVector]:
        """Get all attack vectors with a specific severity.

        Args:
            severity: The severity level to filter by.

        Returns:
            List of vectors with this severity.
        """
        return [v for v in self._vectors.values() if v.severity == severity]

    def get_attacks_by_tag(self, tag: str) -> list[AttackVector]:
        """Get all attack vectors with a specific tag.

        Args:
            tag: The tag to filter by.

        Returns:
            List of vectors containing this tag.
        """
        return [v for v in self._vectors.values() if tag in v.tags]

    def get_attacks_by_owasp(self, owasp_id: OwaspLlmCategory) -> list[AttackVector]:
        """Get all attack vectors mapped to a specific OWASP LLM category.

        Args:
            owasp_id: The OWASP LLM Top 10 category to filter by.

        Returns:
            List of vectors mapped to this OWASP category.
        """
        return [v for v in self._vectors.values() if owasp_id in v.owasp_mapping]

    def search(
        self,
        phase: ScanPhase | None = None,
        category: AttackCategory | None = None,
        severity: Severity | None = None,
        tags: list[str] | None = None,
    ) -> list[AttackVector]:
        """Search vectors with multiple filters (AND logic).

        Args:
            phase: Filter by target phase.
            category: Filter by attack category.
            severity: Filter by severity level.
            tags: Filter by tags (vector must have all specified tags).

        Returns:
            Vectors matching all specified filters.
        """
        results = list(self._vectors.values())

        if phase is not None:
            results = [v for v in results if v.target_phase == phase]
        if category is not None:
            results = [v for v in results if v.category == category]
        if severity is not None:
            results = [v for v in results if v.severity == severity]
        if tags:
            results = [v for v in results if all(t in v.tags for t in tags)]

        return results

    def _load_directory(self, directory: Path) -> None:
        """Load all YAML files from a directory.

        Args:
            directory: Path to directory containing YAML vector files.
        """
        if not directory.is_dir():
            logger.warning("Attack vector directory not found: %s", directory)
            return

        yaml_files = sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml"))
        if not yaml_files:
            logger.warning("No YAML files found in: %s", directory)
            return

        for yaml_file in yaml_files:
            try:
                self._load_file(yaml_file)
            except Exception:
                logger.exception("Failed to load attack vectors from %s", yaml_file)

    def _load_file(self, filepath: Path) -> None:
        """Load attack vectors from a single YAML file.

        Args:
            filepath: Path to the YAML file.
        """
        with filepath.open() as f:
            data = yaml.safe_load(f)

        if not data or "vectors" not in data:
            logger.warning("No vectors found in %s", filepath)
            return

        for vector_data in data["vectors"]:
            try:
                vector = self._parse_vector(vector_data)
                if vector.id in self._vectors:
                    logger.warning(
                        "Duplicate vector ID '%s' in %s — overwriting previous definition",
                        vector.id,
                        filepath,
                    )
                self._vectors[vector.id] = vector
            except Exception:
                logger.exception(
                    "Failed to parse vector '%s' from %s",
                    vector_data.get("id", "unknown"),
                    filepath,
                )

    @staticmethod
    def _parse_vector(data: dict[str, Any]) -> AttackVector:
        """Parse a vector dictionary into an AttackVector model.

        Args:
            data: Raw vector data from YAML.

        Returns:
            Validated AttackVector model.
        """
        prompts = []
        for prompt_data in data.get("prompts", []):
            prompts.append(
                AttackPrompt(
                    template=prompt_data["template"],
                    variables=prompt_data.get("variables", {}),
                    success_indicators=prompt_data.get("success_indicators", []),
                    failure_indicators=prompt_data.get("failure_indicators", []),
                )
            )

        return AttackVector(
            id=data["id"],
            name=data["name"],
            category=AttackCategory(data["category"]),
            target_phase=ScanPhase(data["target_phase"]),
            description=data.get("description", ""),
            severity=data["severity"],
            prompts=prompts,
            tags=data.get("tags", []),
            references=data.get("references", []),
            owasp_mapping=[OwaspLlmCategory(o) for o in data.get("owasp_mapping", [])],
        )
