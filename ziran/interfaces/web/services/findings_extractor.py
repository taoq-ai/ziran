"""Extract findings from scan results into queryable database rows."""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any

from ziran.domain.entities.attack import OWASP_LLM_DESCRIPTIONS, OwaspLlmCategory
from ziran.interfaces.web.models import ComplianceMapping, Finding

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from ziran.interfaces.web.models import Run

logger = logging.getLogger(__name__)


def _compute_fingerprint(target_agent: str, vector_id: str, category: str) -> str:
    """Deterministic SHA-256 fingerprint for deduplication."""
    raw = f"{target_agent}:{vector_id}:{category}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _build_title(vector_name: str, category: str) -> str:
    """Build a human-readable finding title."""
    cat_label = category.replace("_", " ").title()
    return f"{vector_name} ({cat_label})"


async def extract_findings(session: AsyncSession, run: Run) -> list[Finding]:
    """Extract individual findings from a completed run's result_json.

    Iterates ``attack_results`` where ``successful is True``, computes a
    fingerprint for deduplication, and upserts into the ``findings`` table.
    Compliance mappings are created from ``owasp_mapping`` lists.

    Parameters
    ----------
    session:
        Active async database session (caller manages the transaction).
    run:
        The completed Run ORM instance with ``result_json`` populated.

    Returns
    -------
    list[Finding]:
        Newly created or updated Finding rows.
    """
    from sqlalchemy import select

    result_json = run.result_json
    if not result_json:
        return []

    attack_results: list[dict[str, Any]] = result_json.get("attack_results", [])
    if not attack_results:
        return []

    target_agent = run.target_agent
    created: list[Finding] = []

    for ar in attack_results:
        # Only extract successful attacks
        if not ar.get("successful", False):
            continue

        vector_id = ar.get("vector_id", "")
        vector_name = ar.get("vector_name", vector_id)
        category = ar.get("category", "unknown")
        severity = ar.get("severity", "info")

        fingerprint = _compute_fingerprint(target_agent, vector_id, category)

        # Check for existing finding with same fingerprint
        existing_result = await session.execute(
            select(Finding).where(Finding.fingerprint == fingerprint)
        )
        existing = existing_result.scalar_one_or_none()

        if existing is not None:
            # Update run_id to latest but preserve user-set status
            existing.run_id = run.id
            existing.severity = severity
            existing.vector_name = vector_name
            existing.agent_response = ar.get("agent_response")
            existing.prompt_used = ar.get("prompt_used")
            existing.evidence = ar.get("evidence")
            existing.detection_metadata = _build_detection_metadata(ar)
            existing.business_impact = ar.get("business_impact")
            created.append(existing)
            continue

        # Primary OWASP category (first in list, if any)
        owasp_mapping: list[str] = ar.get("owasp_mapping", [])
        primary_owasp = owasp_mapping[0] if owasp_mapping else None

        finding = Finding(
            run_id=run.id,
            fingerprint=fingerprint,
            vector_id=vector_id,
            vector_name=vector_name,
            category=category,
            severity=severity,
            owasp_category=primary_owasp,
            target_agent=target_agent,
            status="open",
            title=_build_title(vector_name, category),
            description=ar.get("description"),
            remediation=ar.get("remediation"),
            prompt_used=ar.get("prompt_used"),
            agent_response=ar.get("agent_response"),
            evidence=ar.get("evidence"),
            detection_metadata=_build_detection_metadata(ar),
            business_impact=ar.get("business_impact"),
        )
        session.add(finding)
        await session.flush()  # Ensure finding.id is available for mappings

        # Create compliance mappings from owasp_mapping list
        for owasp_cat in owasp_mapping:
            try:
                cat_enum = OwaspLlmCategory(owasp_cat)
                control_name = OWASP_LLM_DESCRIPTIONS.get(cat_enum, owasp_cat)
            except ValueError:
                control_name = owasp_cat

            mapping = ComplianceMapping(
                finding_id=finding.id,
                framework="owasp_llm",
                control_id=owasp_cat,
                control_name=control_name,
            )
            session.add(mapping)

        created.append(finding)

    return created


def _build_detection_metadata(ar: dict[str, Any]) -> dict[str, Any]:
    """Build detection metadata dict from attack result fields."""
    meta: dict[str, Any] = {}
    if ar.get("encoding_applied"):
        meta["encoding_applied"] = ar["encoding_applied"]
    if ar.get("quality_score") is not None:
        meta["quality_score"] = ar["quality_score"]
    if ar.get("harm_category"):
        meta["harm_category"] = ar["harm_category"]
    return meta if meta else {}
