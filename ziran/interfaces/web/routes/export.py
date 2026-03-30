"""Export endpoints — CSV, JSON, YAML, Markdown."""

import csv
import io
import uuid
from collections.abc import Generator
from typing import Annotated, Any

import yaml
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ziran.interfaces.web.dependencies import get_db
from ziran.interfaces.web.models import Finding, Run

router = APIRouter()

_CSV_COLUMNS = [
    "id",
    "severity",
    "title",
    "category",
    "owasp_category",
    "target_agent",
    "status",
    "vector_name",
    "created_at",
]


def _findings_to_csv(findings: list[Any]) -> Generator[str, None, None]:
    """Yield CSV rows from findings."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_COLUMNS)
    yield buf.getvalue()
    buf.seek(0)
    buf.truncate()

    for f in findings:
        writer.writerow([getattr(f, col, "") for col in _CSV_COLUMNS])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()


async def _filtered_findings(
    db: AsyncSession,
    *,
    run_id: uuid.UUID | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    owasp: str | None = None,
    target: str | None = None,
    search: str | None = None,
) -> list[Any]:
    """Apply filters and return all matching findings (no pagination)."""
    query = select(Finding).order_by(Finding.created_at.desc())
    if run_id:
        query = query.where(Finding.run_id == run_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if category:
        query = query.where(Finding.category == category)
    if owasp:
        query = query.where(Finding.owasp_category == owasp)
    if target:
        query = query.where(Finding.target_agent == target)
    if search:
        pattern = f"%{search}%"
        query = query.where(
            Finding.title.ilike(pattern)
            | Finding.description.ilike(pattern)
            | Finding.vector_name.ilike(pattern)
        )
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/export/findings.csv")
async def export_findings_csv(
    db: Annotated[AsyncSession, Depends(get_db)],
    run_id: uuid.UUID | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    owasp: str | None = None,
    target: str | None = None,
    search: str | None = None,
) -> StreamingResponse:
    """Export findings as CSV with current filters."""
    findings = await _filtered_findings(
        db,
        run_id=run_id,
        severity=severity,
        status=status,
        category=category,
        owasp=owasp,
        target=target,
        search=search,
    )
    return StreamingResponse(
        _findings_to_csv(findings),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="findings.csv"'},
    )


@router.get("/export/findings.json")
async def export_findings_json(
    db: Annotated[AsyncSession, Depends(get_db)],
    run_id: uuid.UUID | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    owasp: str | None = None,
    target: str | None = None,
    search: str | None = None,
) -> Response:
    """Export findings as JSON."""
    from ziran.interfaces.web.schemas import FindingSummary

    findings = await _filtered_findings(
        db,
        run_id=run_id,
        severity=severity,
        status=status,
        category=category,
        owasp=owasp,
        target=target,
        search=search,
    )
    items = [FindingSummary.model_validate(f).model_dump(mode="json") for f in findings]
    import json

    content = json.dumps(items, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="findings.json"'},
    )


@router.get("/export/run/{run_id}.yaml")
async def export_run_yaml(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """Export run configuration as YAML."""
    run = await db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    config = run.config_json or {}
    content = yaml.dump(config, default_flow_style=False, sort_keys=False)
    return Response(
        content=content,
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="run-{run_id}.yaml"'},
    )


@router.get("/export/run/{run_id}.md")
async def export_run_markdown(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """Export run summary as Markdown report."""
    run = await db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    # Fetch findings for this run
    result = await db.execute(
        select(Finding).where(Finding.run_id == run_id).order_by(Finding.severity)
    )
    findings = result.scalars().all()

    md = _build_markdown_report(run, list(findings))
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="run-{run_id}.md"'},
    )


def _build_markdown_report(run: Any, findings: list[Any]) -> str:
    """Build a Markdown report for a run."""
    lines: list[str] = []
    name = run.name or f"Run {run.id}"
    lines.append(f"# Security Scan Report: {name}\n")
    lines.append(f"**Target**: {run.target_agent}  ")
    lines.append(f"**Status**: {run.status}  ")
    lines.append(f"**Coverage**: {run.coverage_level}  ")
    lines.append(f"**Strategy**: {run.strategy}  ")
    lines.append(f"**Created**: {run.created_at}  ")
    if run.completed_at:
        lines.append(f"**Completed**: {run.completed_at}  ")
    lines.append("")

    lines.append("## Summary\n")
    lines.append(f"- **Total Vulnerabilities**: {run.total_vulnerabilities}")
    lines.append(f"- **Critical Paths**: {run.critical_paths_count}")
    lines.append(f"- **Trust Score**: {run.final_trust_score}")
    lines.append(f"- **Total Tokens**: {run.total_tokens}")
    lines.append("")

    if findings:
        lines.append("## Findings\n")
        lines.append("| Severity | Title | Category | Status |")
        lines.append("|----------|-------|----------|--------|")
        for f in findings:
            lines.append(f"| {f.severity} | {f.title} | {f.category} | {f.status} |")
        lines.append("")

    lines.append("## Configuration\n")
    lines.append("```yaml")
    config = run.config_json or {}
    lines.append(yaml.dump(config, default_flow_style=False, sort_keys=False).strip())
    lines.append("```\n")

    lines.append("---\n")
    lines.append("*Generated by [ZIRAN](https://github.com/taoq-ai/ziran)*")

    return "\n".join(lines)
