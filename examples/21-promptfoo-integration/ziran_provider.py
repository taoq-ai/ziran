"""ZIRAN Promptfoo provider — sends prompts through ZIRAN's security analysis.

This file is referenced in promptfooconfig.yaml as:
    providers:
      - id: "file://ziran_provider.py"

Promptfoo calls ``call_api()`` for each test case. We delegate to
ZIRAN's built-in Promptfoo bridge which handles adapter creation,
prompt invocation, and metadata collection.

See: https://www.promptfoo.dev/docs/providers/python/
"""

from __future__ import annotations

from typing import Any

from ziran.integrations.promptfoo.provider import call_api as _ziran_call_api


def call_api(
    prompt: str,
    options: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Promptfoo provider entry point.

    Delegates to ZIRAN's built-in provider bridge which:
    1. Creates an HttpAgentAdapter from the config
    2. Sends the prompt to the target agent
    3. Collects tool calls, token usage, and indicator matches
    4. Returns a Promptfoo-compatible response dict
    """
    return _ziran_call_api(prompt, options, context)
