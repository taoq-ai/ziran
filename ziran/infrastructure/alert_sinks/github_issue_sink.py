"""GitHub issue alert sink with stateless, marker-based deduplication."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from ziran.domain.entities.alerting import DeliveryResult
from ziran.domain.ports.alert_sink import AlertSink

if TYPE_CHECKING:
    from ziran.domain.entities.alerting import AlertableFinding

_API_ROOT = "https://api.github.com"
_MARKER_PREFIX = "ziran-fingerprint:"


def marker(fingerprint: str) -> str:
    """Hidden HTML-comment marker embedded in issue bodies for dedup."""
    return f"<!-- {_MARKER_PREFIX} {fingerprint} -->"


class GitHubIssueSink(AlertSink):
    """Opens a GitHub issue per finding, deduping via an embedded fingerprint marker.

    Dedup is stateless: before creating, the sink searches open *and* closed
    issues for the marker via the Search API; a hit short-circuits to ``deduped``.
    """

    name = "github_issue"

    def __init__(
        self,
        repo: str,
        token: str | None,
        labels: list[str] | None = None,
        assignees: list[str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._repo = repo
        self._token = token
        self._labels = labels or []
        self._assignees = assignees or []
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _body(self, finding: AlertableFinding) -> str:
        lines = [finding.summary, ""]
        for key, value in finding.fields.items():
            lines.append(f"- **{key}:** {value}")
        if finding.links:
            lines.append("")
            for link in finding.links:
                lines.append(f"- [{link.label}]({link.url})")
        if finding.remediation:
            lines.extend(["", "## Suggested remediation", "", finding.remediation])
        lines.extend(["", marker(finding.fingerprint)])
        return "\n".join(lines)

    async def emit(self, finding: AlertableFinding) -> DeliveryResult:
        if not self._token:
            return DeliveryResult(
                sink_name=self.name,
                fingerprint=finding.fingerprint,
                status="failed",
                detail="no GitHub token configured (set token or GITHUB_TOKEN)",
            )
        try:
            async with httpx.AsyncClient(timeout=self._timeout, headers=self._headers()) as client:
                existing = await self._find_existing(client, finding.fingerprint)
                if existing is not None:
                    return DeliveryResult(
                        sink_name=self.name,
                        fingerprint=finding.fingerprint,
                        status="deduped",
                        detail=existing,
                    )
                return await self._create(client, finding)
        except httpx.HTTPError as exc:
            return DeliveryResult(
                sink_name=self.name,
                fingerprint=finding.fingerprint,
                status="failed",
                detail=f"github request error: {exc}",
            )

    async def _find_existing(self, client: httpx.AsyncClient, fingerprint: str) -> str | None:
        query = f'repo:{self._repo} in:body "{_MARKER_PREFIX} {fingerprint}" is:issue'
        resp = await client.get(f"{_API_ROOT}/search/issues", params={"q": query})
        if resp.status_code != httpx.codes.OK:
            return None
        items = resp.json().get("items", [])
        if items:
            url: str = items[0].get("html_url", "")
            return url
        return None

    async def _create(self, client: httpx.AsyncClient, finding: AlertableFinding) -> DeliveryResult:
        payload: dict[str, Any] = {
            "title": f"{finding.kind}: {finding.title}"[:256],
            "body": self._body(finding),
        }
        if self._labels:
            payload["labels"] = self._labels
        if self._assignees:
            payload["assignees"] = self._assignees
        resp = await client.post(f"{_API_ROOT}/repos/{self._repo}/issues", json=payload)
        if resp.status_code == httpx.codes.CREATED:
            return DeliveryResult(
                sink_name=self.name,
                fingerprint=finding.fingerprint,
                status="sent",
                detail=resp.json().get("html_url"),
            )
        return DeliveryResult(
            sink_name=self.name,
            fingerprint=finding.fingerprint,
            status="failed",
            detail=f"github responded {resp.status_code}: {resp.text[:200]}",
        )
