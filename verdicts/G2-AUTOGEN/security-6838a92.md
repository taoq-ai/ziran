Verdict: PASS
Gate: security
Item: G2-AUTOGEN
PR: taoq-ai/ziran#507
Head: 6838a9275f103d8aeb2d911b4657a71b7b49f9fd
Confidence: medium

## Findings
- [low] ziran/infrastructure/adapters/autogen_adapter.py:76 blocks: no. Every list_tools() call on an MCP workbench starts that server (the command the user's own agent file configures), and the adapter never stops it. scan calls it twice per agent (discover_capabilities, then discover_structure). The trust boundary does not change, because loading the file already runs the user's code, and docs/guides/adapters.md states the side effect. The server process stays alive until ziran exits, and MCP-supplied tool names and descriptions are untrusted text in reports, as with the other adapters (CWE-404 note).
- [low] ziran/application/factories.py:77 blocks: no. Untested: a file that defines both `team` and `agent` returns `team`. Mutant M2 (fallbacks put before object_name) was killed only by the wording of the error message. A test for the both-names case is missing.

## Probes
- Trust model: _load_python_object still runs the user file in process with importlib exec_module, the same as the langgraph, openai-agents and crewai paths. Probe: a target file that appends to a counter file on import and defines only `agent` was loaded through load_agent_adapter("autogen", ...). It ran once (`execs: 1`) and returned the UserProxyAgent. Known-negative: a file defining only `crew` raised ValueError "Object 'team' or 'agent' not found". The pre-existing double run on the agentcore path (factories.py:274/278, `invoke` then `app`) is outside this diff.
- Type guard: AutoGenAdapter(object()), AutoGenAdapter("team") and AutoGenAdapter(None) all raise TypeError. Mutant M1 (guard replaced by `if False:`) in a fresh git archive copy was killed by test_autogen_adapter.py::TestConstruction::test_rejects_non_autogen_object.
- Example execute_code is a stub that returns "exit code 0". discover only calls StaticWorkbench.list_tools(), which reads tool.schema (autogen_core/tools/_static_workbench.py:68) and never calls a tool. Tests use a fake autogen_ext fixture and a stub ChatCompletionClient, so nothing runs and nothing reaches the network.
- Secrets: the example reads OPENAI_API_KEY from the environment, and its fallback "unused-by-discover" is a placeholder, not a credential. The adapter logs only tool_count and dangerous_count, never prompts, outputs or keys.
- Supply chain: the uv.lock diff adds only autogen-agentchat 0.7.5 and autogen-core 0.7.5, both registry wheels (py3-none-any) with sha256 hashes. Their transitive deps (jsonref, opentelemetry-api, pillow, protobuf, pydantic, typing-extensions) were already locked. The extra is pinned >=0.7,<0.8. No workflow changes; no pull_request_target in .github/workflows.
- pip-audit, run as CI runs it (uv export --frozen --all-extras, then uvx pip-audit --no-deps --disable-pip with the ci.yml ignore list): "No known vulnerabilities found, 8 ignored". uv lock --check: current (215 packages).
- Static: ruff check passes on the changed files, and so does an extra uvx ruff --select S (bandit rules) on autogen_adapter.py, factories.py and the example agent.py.
- Tests at head: test_autogen_adapter.py, test_cli_main.py and application/test_factories.py: 169 passed, 2 skipped.
- Confidence medium: the McpWorkbench start behaviour comes from AutoGen's documented lazy start and was not run here, because autogen-ext is not in the lock.

## Residual risk
Introspection relies on private AgentChat attributes that are pinned below 0.8. MCP servers started during discovery stay alive until the process exits.
