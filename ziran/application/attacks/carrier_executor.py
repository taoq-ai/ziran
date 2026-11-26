"""Plant or attach a vector's carrier file, then run its prompts (spec 112).

The file goes where the target's tools read it (a workspace folder, a knowledge-base folder,
a folder served as web pages) or with the message, for an adapter that lists its media type
in ``attachment_types``. Each prompt names it through ``{carrier}``. The hidden text is the
payload the side-effect detector's P1 rule reads, so a finding still needs one of its values
in a tool call's arguments. A vector the scan cannot deliver is skipped as unmeasured.
"""

from __future__ import annotations

import asyncio
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ziran.application.attacks.carriers import build
from ziran.application.detectors.ensemble import review_evidence
from ziran.application.detectors.side_effect import get_side_effect_summary
from ziran.domain.entities.attack import AttackResult, TokenUsage, get_business_impacts
from ziran.domain.interfaces.adapter import scan_metadata
from ziran.domain.replies import is_error_response
from ziran.infrastructure.logging.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from ziran.application.detectors.pipeline import DetectorPipeline
    from ziran.domain.entities.attack import AttackPrompt, AttackVector
    from ziran.domain.interfaces.adapter import Attachment, BaseAgentAdapter

logger = get_logger(__name__)

_SITE_KEYS = {
    "workspace": "workspace_dir",
    "knowledge_base": "knowledge_base_dir",
    "page": "page_dir",
}


class CarrierSites(BaseModel):
    """Where a scan plants carrier files (``ziran scan --carriers <yaml>``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    workspace_dir: Path | None = Field(default=None, description="A folder the agent's tools read")
    knowledge_base_dir: Path | None = Field(
        default=None, description="A folder the agent's knowledge base ingests"
    )
    page_dir: Path | None = Field(default=None, description="A folder served at page_url")
    page_url: str | None = Field(default=None, description="The http(s) URL of page_dir")

    @model_validator(mode="after")
    def _page_pair(self) -> CarrierSites:
        if (self.page_dir is None) != (self.page_url is None):
            raise ValueError("page_dir and page_url go together")
        if self.page_url is not None and urlsplit(self.page_url).scheme not in ("http", "https"):
            raise ValueError("page_url must be an http or https URL")
        return self


def _plant(path: Path, data: bytes) -> Path:
    with path.open("xb") as f:  # exclusive: never overwrite a file of the target's
        f.write(data)
    return path


def _result(
    attack: AttackVector, successful: bool, evidence: dict[str, Any], **extra: Any
) -> AttackResult:
    return AttackResult(
        vector_id=attack.id,
        vector_name=attack.name,
        category=attack.category,
        severity=attack.severity,
        successful=successful,
        evidence=evidence,
        owasp_mapping=attack.owasp_mapping,
        owasp_agentic_mapping=attack.owasp_agentic_mapping,
        atlas_mapping=attack.atlas_mapping,
        business_impact=get_business_impacts(attack.category, attack.severity),
        harm_category=attack.harm_category,
        **extra,
    )


class CarrierExecutor:
    """Runs one carrier vector: deliver the file, send each prompt, evaluate, clean up."""

    def __init__(self, adapter: BaseAgentAdapter, sites: CarrierSites | None) -> None:
        self._adapter = adapter
        self._sites = sites

    def _folder(self, delivery: str) -> Path | None:
        key = _SITE_KEYS.get(delivery)
        return getattr(self._sites, key) if key and self._sites is not None else None

    def _unavailable(self, delivery: str, media_type: str) -> str | None:
        if delivery == "attachment":
            if media_type in self._adapter.attachment_types:
                return None
            return f"{type(self._adapter).__name__} cannot send a {media_type} attachment"
        if self._folder(delivery) is None:
            return f"no {delivery} folder: pass --carriers with {_SITE_KEYS[delivery]}"
        return None

    def _ref(self, delivery: str, file: Attachment, planted: Path | None) -> str:
        # a file name, not a host path: the agent may see the folder under another path
        name = planted.name if planted is not None else file.filename
        if delivery != "page":
            return name
        assert self._sites is not None and self._sites.page_url is not None
        return f"{self._sites.page_url.rstrip('/')}/{name}"

    async def execute(
        self,
        attack: AttackVector,
        pipeline: DetectorPipeline,
        render: Callable[[AttackPrompt], str],
    ) -> AttackResult:
        carrier = attack.carrier
        assert carrier is not None
        file = build(carrier)
        record = {
            "format": carrier.format,
            "placement": carrier.placement,
            "delivery": carrier.delivery,
            "media_type": file.media_type,
        }
        reason = self._unavailable(carrier.delivery, file.media_type)
        folder = self._folder(carrier.delivery)
        planted: Path | None = None
        if reason is None and folder is not None:
            name = f"{carrier.name}-{secrets.token_hex(4)}.{carrier.format}"
            try:
                planted = await asyncio.to_thread(_plant, folder / name, file.data)
            except OSError as exc:
                reason = f"could not plant the file: {type(exc).__name__}"
        if reason is not None:
            logger.warning("carrier_skipped", vector_id=attack.id, reason=reason)
            evidence = {"skipped": reason, "outcome": "unmeasured", "carrier": record}
            return _result(attack, False, evidence)
        try:
            ref = self._ref(carrier.delivery, file, planted)
            sent = {"attachments": [file]} if planted is None else {}
            return await self._run(attack, pipeline, render, ref, sent, record)
        finally:
            if planted is not None:
                await asyncio.to_thread(planted.unlink, missing_ok=True)

    async def _run(
        self,
        attack: AttackVector,
        pipeline: DetectorPipeline,
        render: Callable[[AttackPrompt], str],
        ref: str,
        sent: dict[str, Any],
        record: dict[str, str],
    ) -> AttackResult:
        assert attack.carrier is not None
        usage = TokenUsage()
        answered = 0
        review: dict[str, Any] = {}
        last: dict[str, Any] = {}
        for spec in attack.prompts:
            prompt = render(spec).replace("{carrier}", ref)
            try:
                response = await self._adapter.invoke(prompt, **sent)
                # the hidden text is the attack: the prompt names the file, the task's own value
                response.metadata = scan_metadata(response.metadata, attack.carrier.text)
                usage = usage + TokenUsage(
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    total_tokens=response.total_tokens,
                )
                if is_error_response(response.content):
                    continue
                last = {"agent_response": response.content, "prompt_used": prompt}
                verdict = await pipeline.evaluate(prompt, response, spec, attack)
            except Exception as exc:  # one prompt's failure is a prompt error, as in AttackExecutor
                logger.warning(
                    "carrier_prompt_error", vector_id=attack.id, error=type(exc).__name__
                )
                continue
            answered += 1
            if verdict.needs_review:
                review = review_evidence(verdict)
            if verdict.successful:
                evidence = {
                    "response_snippet": response.content[:500],
                    "tool_calls": response.tool_calls,
                    "matched_indicators": verdict.matched_indicators,
                    "detector_scores": {r.detector_name: r.score for r in verdict.detector_results},
                    "detector_reasoning": verdict.reasoning,
                    "side_effects": get_side_effect_summary(response.tool_calls),
                    **review_evidence(verdict),
                    "carrier": record,
                }
                return _result(attack, True, evidence, **last, token_usage=usage)
        evidence = {"note": "The carrier did not lead to a finding", **review, "carrier": record}
        if answered < len(attack.prompts):  # swallowed failures block caching (spec 049)
            evidence["prompt_errors"] = len(attack.prompts) - answered
        if not answered:
            evidence["outcome"] = "unmeasured"
        return _result(attack, False, evidence, **last, token_usage=usage)
