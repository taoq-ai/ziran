"""Prompt registry for the hybrid detector's model jobs (spec 064).

A prompt is the file ``prompts/<job>/v<N>.md`` beside this module. A version that has merged
is never edited: a changed prompt is a new version, so a stored reply is never replayed under
wording it was not given. ``tests/unit/test_hybrid_prompts.py`` enforces this against the base
branch.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from pydantic import BaseModel

PROMPTS = Path(__file__).resolve().parent / "prompts"
_JOB = re.compile(r"[a-z][a-z0-9_]*")


class Prompt(BaseModel):
    """One prompt version: its text and the sha256 of its file's bytes."""

    model_config = {"frozen": True}

    job: str
    version: int
    text: str
    sha256: str


def load(job: str, version: int, *, root: Path = PROMPTS) -> Prompt:
    """Read ``<root>/<job>/v<version>.md``.

    Raises:
        ValueError: the job is not a plain lowercase name or the version not an int of 0 or more.
        FileNotFoundError: no such version.
    """
    if not _JOB.fullmatch(job) or type(version) is not int or version < 0:
        raise ValueError(f"no prompt name: job {job!r}, version {version!r}")
    data = (root / job / f"v{version}.md").read_bytes()
    return Prompt(
        job=job,
        version=version,
        text=data.decode("utf-8"),
        sha256=hashlib.sha256(data).hexdigest(),
    )
