Verdict: PASS
Gate: security
Item: G2-OPENAI-AGENTS
PR: taoq-ai/ziran#502
Head: 24b1f1997d9bc0e2fda60e5d6672bbacb7ddfcdc
Confidence: high

## Findings
- [low] ziran/infrastructure/adapters/openai_agents_adapter.py:126 blocks: no. Runner.run is called without a RunConfig, so the SDK defaults hold: tracing on, OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA defaults to "true" (agents/run_config.py:53), and with OPENAI_API_KEY set, spans carrying attack prompts and tool outputs go to https://api.openai.com/v1/traces/ingest (agents/tracing/processors.py:45). That host is still OpenAI even when the agent's model is not. The guide documents it; it should also name the opt-out (OPENAI_AGENTS_DISABLE_TRACING=1 or set_tracing_disabled in the agent file), because the scanner never forwards kwargs or a run_config to invoke (CWE-359, OWASP LLM02).
- [low] ziran/infrastructure/adapters/openai_agents_adapter.py:67 blocks: no. _walk deduplicates by agent name, so a second agent in the handoff tree that reuses a name has its tools left out of discovery. In a probe, delete_all on an inner agent named "x" was missing from discover_capabilities. This is a documented limit ("Agents are identified by name"), and the agent file is the operator's own, so there is no trust boundary (CWE-1023).

## Probes
- Code execution: openai-agents loads the user file through the existing _load_python_object (factories.py:42, exec_module of an operator-supplied path), the same trust model as langchain and langgraph. No new execution path; the adapter only adds an isinstance(agent, Agent) check.
- Supply chain: pyproject adds openai-agents>=0.20,<1 behind its own extra and in `all`. uv.lock adds openai-agents 0.20.0 and griffelib 2.4.1 and moves openai from 2.43.0 to 2.54.0, all from the pypi.org registry and pinned by sha256. The openai-agents wheel is py3-none-any, so no build or install script runs; the installed METADATA says OpenAI and github.com/openai/openai-agents-python, and its Requires-Dist names griffelib<3,>=2 and openai>=2.45.0. No .github workflow changes, and no pull_request_target.
- Scanner: `uv lock --check` passes at the head (213 packages). The CI dependency-audit step, re-run exactly (uv export --frozen --all-extras, then uvx pip-audit --no-deps --disable-pip with the 7 CI ignores), found no known vulnerabilities (8 ignored).
- Secrets: the adapter logs only tool counts (openai_agents_tools_discovered). The ImportError adds only the import error text. No key is read or echoed. The example needs OPENAI_API_KEY only from the environment. The tests call set_tracing_disabled(True) and use a stub model, so no network.
- Untrusted model output: tool-call arguments go through json.loads, with the raw string kept on a decode error, and become AgentResponse data only, never instructions. Handoff traversal is cycle safe (by name) and reads the private _agent_ref through getattr with a callable check.
- Known-positive and known-negative: OpenAIAgentsAdapter(object()) raises TypeError. load_agent_adapter("openai-agents", the examples/26 agent.py) finds the agent and classifies read_file and send_email as dangerous and lookup_invoice as not.
- Mutants, in a git archive copy: reversing the isinstance guard fails test_rejects_non_agent. Inverting the input_filter delegation fails test_input_filter_is_partial_context. Tests: 14 passed at the head.
- Confidence high: small surface, no new trust boundary, and the lock is audited with the repository's own gate. It would change if openai-agents 0.2x shipped a post-0.20 install hook or if the scanner started forwarding operator kwargs.

## Residual risk
With tracing at the SDK default, scan traffic (attack prompts and tool outputs, which may include data the scanned tools read) is sent to OpenAI's trace store under the operator's key. The operator controls this, but only through an SDK env var or a call in the agent file.
