"""ZIRAN Promptfoo assertions — evaluates security properties of responses.

This file is referenced in promptfooconfig.yaml as:
    assert:
      - type: "file://ziran_assertions.py"
        config:
          max_tool_calls: 0
          blocked_indicators: ["secret"]

Promptfoo calls ``get_assert()`` after each provider response.
We delegate to ZIRAN's built-in assertion module.

See: https://www.promptfoo.dev/docs/configuration/expected-outputs/
"""

from __future__ import annotations

from typing import Any

from ziran.integrations.promptfoo.assertions import get_assert as _ziran_get_assert


def get_assert(
    output: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Promptfoo assertion entry point.

    Delegates to ZIRAN's built-in assertion module which checks:
    - max_vulnerabilities: fail if vulnerability count exceeds threshold
    - min_trust_score: fail if trust score below threshold
    - max_tool_calls: fail if tool call count exceeds limit
    - blocked_indicators: fail if blocked terms appear in output
    """
    return _ziran_get_assert(output, context)
