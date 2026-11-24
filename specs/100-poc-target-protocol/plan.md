# Plan: PoCs reproduce against OpenAI-protocol and custom-path HTTP targets

No new dependency. The application layer gains a domain import (`ProtocolType`, `OpenAIConfig`,
`RestConfig`); it imports no infrastructure.

- `ziran/application/poc/generator.py`: `PoCGenerator` takes `target: TargetConfig | None`.
  `_request(prompt, endpoint)` returns the method, URL and JSON body: the OpenAI handler's
  single-turn request for `openai`, the REST handler's for `rest` (a missing protocol block
  falls back to the defaults, as the handlers do), `{"message": prompt}` otherwise. Both
  scripts use it. `_indicators(result)` keeps the matched indicators found in the recorded
  reply.
- cURL PoC: spec 099's layout. The body is `json.dumps` of the built body; the method is a
  quoted `-X` word. Exit codes flip to 0 reproduced, 1 not; a finding with no text indicator
  exits 2 before any grep.
- Python PoC, `openai` and `rest` targets (`_http_target`): module constants as `repr()` literals (spec 099), plus `METHOD`,
  `DEFAULT_ENDPOINT` and `BODY = json.loads(<repr of the same JSON the cURL PoC sends>)`.
  `reproduce(endpoint)` sends with `httpx.request`, walks every string in the JSON reply and
  returns the exit code; `__main__` passes `sys.argv[1]` when given.
- Python PoC otherwise: the base adapter-driven `reproduce(adapter)` body, configured imports and run instructions. The two bodies are module constants, never passed through `str.format`.
- `generate_all` adds the cURL PoC for `openai` and `rest` targets.
- `poc --protocol` overrides the loaded target's protocol, as `load_remote_adapter` does for `scan`.
- `HttpAgentAdapter.protocol`: the configured protocol, set to the detected one after `auto`
  resolves. `scan` passes its target config, with that protocol, to `_save_results`; `poc`
  gains `--target <yaml>`.
- Docs: `docs/reference/cli.md` (`--target`, endpoint argument, exit codes); the default run
  instructions in `config.py` and `default_config.yaml`.

Tests in `tests/unit/test_poc_target_protocol.py`: a `ThreadingHTTPServer` stub on 127.0.0.1
per protocol (OpenAI-compatible; REST with `PUT /api/agent/chat`, a custom message field and an
extra body). The real handler and both PoCs send to it, and the requests must be equal.
Leak and fix runs check exit codes 0 and 1, a hostile prompt checks no command runs, and there
are tests for exit 2, the tool-call fallback, `auto`, the adapter's detected protocol, `poc
--target` and `_save_results`. The old-contract tests in `test_poc_generator.py` move to the
new exit codes and the httpx driver. Mutants run in a `git archive` copy under
`timeout -s KILL 120`.
