"""Read-only access to the bundled attack vector library."""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, HTTPException, Query

from ziran.application.attacks.library import get_attack_library
from ziran.interfaces.web.schemas import (
    LibraryStatsResponse,
    PromptTemplate,
    VectorDetail,
    VectorListResponse,
    VectorSummary,
)

router = APIRouter()


def _vector_to_summary(v: object) -> VectorSummary:
    """Convert an AttackVector domain model to a VectorSummary schema."""
    return VectorSummary(
        id=v.id,  # type: ignore[attr-defined]
        name=v.name,  # type: ignore[attr-defined]
        category=str(v.category),  # type: ignore[attr-defined]
        severity=v.severity,  # type: ignore[attr-defined]
        target_phase=str(v.target_phase),  # type: ignore[attr-defined]
        description=v.description,  # type: ignore[attr-defined]
        tags=v.tags,  # type: ignore[attr-defined]
        owasp_mapping=[str(o) for o in v.owasp_mapping],  # type: ignore[attr-defined]
        prompt_count=v.prompt_count,  # type: ignore[attr-defined]
        protocol_filter=v.protocol_filter,  # type: ignore[attr-defined]
    )


def _vector_to_detail(v: object) -> VectorDetail:
    """Convert an AttackVector domain model to a VectorDetail schema."""
    return VectorDetail(
        id=v.id,  # type: ignore[attr-defined]
        name=v.name,  # type: ignore[attr-defined]
        category=str(v.category),  # type: ignore[attr-defined]
        severity=v.severity,  # type: ignore[attr-defined]
        target_phase=str(v.target_phase),  # type: ignore[attr-defined]
        description=v.description,  # type: ignore[attr-defined]
        tags=v.tags,  # type: ignore[attr-defined]
        owasp_mapping=[str(o) for o in v.owasp_mapping],  # type: ignore[attr-defined]
        prompt_count=v.prompt_count,  # type: ignore[attr-defined]
        protocol_filter=v.protocol_filter,  # type: ignore[attr-defined]
        references=v.references,  # type: ignore[attr-defined]
        prompts=[
            PromptTemplate(
                template=p.template,
                variables=p.variables,
                success_indicators=p.success_indicators,
                failure_indicators=p.failure_indicators,
            )
            for p in v.prompts  # type: ignore[attr-defined]
        ],
    )


@router.get("/vectors", response_model=VectorListResponse)
async def list_vectors(
    category: str | None = None,
    severity: str | None = None,
    phase: str | None = None,
    owasp: str | None = None,
    search: str | None = Query(default=None, description="Search by name, description, or tags"),
) -> VectorListResponse:
    """List all attack vectors with optional filtering."""
    library = get_attack_library()
    vectors = library.vectors

    if category:
        vectors = [v for v in vectors if str(v.category) == category]
    if severity:
        vectors = [v for v in vectors if v.severity == severity]
    if phase:
        vectors = [v for v in vectors if str(v.target_phase) == phase]
    if owasp:
        vectors = [v for v in vectors if owasp in [str(o) for o in v.owasp_mapping]]
    if search:
        term = search.lower()
        vectors = [
            v
            for v in vectors
            if term in v.name.lower()
            or term in v.description.lower()
            or any(term in tag.lower() for tag in v.tags)
        ]

    return VectorListResponse(
        vectors=[_vector_to_summary(v) for v in vectors],
        total=len(vectors),
    )


@router.get("/vectors/{vector_id}", response_model=VectorDetail)
async def get_vector(vector_id: str) -> VectorDetail:
    """Get full detail for a specific attack vector."""
    library = get_attack_library()
    vector = library.get_vector(vector_id)
    if not vector:
        raise HTTPException(status_code=404, detail="Vector not found")
    return _vector_to_detail(vector)


@router.get("/stats", response_model=LibraryStatsResponse)
async def library_stats() -> LibraryStatsResponse:
    """Aggregate statistics for the attack vector library."""
    library = get_attack_library()
    vectors = library.vectors

    total_prompts = sum(v.prompt_count for v in vectors)

    by_category: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    by_owasp: dict[str, int] = defaultdict(int)

    for v in vectors:
        by_category[str(v.category)] += 1
        by_severity[v.severity] += 1
        for o in v.owasp_mapping:
            by_owasp[str(o)] += 1

    return LibraryStatsResponse(
        total_vectors=len(vectors),
        total_prompts=total_prompts,
        by_category=dict(by_category),
        by_severity=dict(by_severity),
        by_owasp=dict(by_owasp),
    )
