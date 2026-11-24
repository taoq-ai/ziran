# Plan: Generated PoCs check for the canaries the scan recorded

No new dependency; stdlib `re` and `json`, already imported.

- `ziran/application/poc/generator.py`: `_indicators(result)` gathers the recorded reply and
  every string in each recorded tool call's arguments (`_parsed` decodes a JSON string,
  `_strings` walks the value). It takes the canary tokens (`_CANARY`, with a digit) from that
  text first, then the matched indicators found in it. Both scripts already read
  `_indicators`, so the cURL grep and the Python check change together.
- The httpx Python PoC body (`_PY_HTTP_REPRODUCE`): `_texts` no longer collects tool calls,
  and the tool-call success branch goes. `_texts` already walks every string of the parsed
  JSON, so tool-call arguments are matched.
- The adapter-driven body, the request builder and the quoting are untouched.
- Docs: `docs/reference/cli.md`, the PoC check and exit-code lines.

Tests in `tests/unit/test_poc_target_protocol.py`: the OpenAI stub returns a tool call whose
JSON-string arguments carry the canary while the reply text does not; both PoCs exit 0. The
same stub with a fresh canary in the call makes both exit 1. A parametrized unit test covers
`_indicators` on JSON-string, dict and non-JSON arguments, the `input` key, a canary in the
reply, a tool named like a canary and a bare word. The tool-call fallback test moves to exit 2,
and the two no-indicator tests get a reply without a canary.
