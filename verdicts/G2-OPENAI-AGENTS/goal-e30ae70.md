Verdict: PASS
Gate: goal
Item: G2-OPENAI-AGENTS
PR: taoq-ai/ziran#502
Head: e30ae7044c8ab33ae931fb3d8352a38d6b360e98
Confidence: medium

## Findings
- [low] ziran/interfaces/cli/init_command.py:18 blocks: no. `openai-agents` is not in `_FRAMEWORKS`; the promise names only the scan and discover Choice lists, the factory and the ImportError, so it is not required. `ziran init` writes a `ziran.yaml` nothing reads, and `anthropic` is also absent; spec 050 did add `langgraph`, so one word would make it consistent.
- [low] ziran/infrastructure/adapters/openai_agents_adapter.py:121 blocks: no. Two distinct agents with the same name merge into one node and the edge appears twice; SDK exceptions (hallucinated tool, max turns, guardrail tripwire) leave `invoke` and the attack executor records them as errors, as for the other adapters.

## Probes
- closed: missing `agents.*` mypy override (my FIX at 24b1f19) at e30ae70. `pyproject.toml` now lists it. CI `typecheck` at this head: pass. In a fresh `git archive e30ae70` copy with openai-agents uninstalled, `mypy ziran/infrastructure/adapters/openai_agents_adapter.py` gives `Success: no issues found in 1 source file` (was 2 import-not-found errors).
- Acceptance 1-5 re-checked in a fresh `git archive` copy of e30ae70: the adapter tests are 16 passed on openai-agents 0.20.0 and 16 passed on 0.25.0 (the two new tests are the handoff() sub-agent tool and the concurrent-turn one). Covers capability discovery across handoffs, topology plus scanner import, refusal plus send_email firing the side-effect detector, example loading and the not-installed error naming `uv sync --extra openai-agents`.
- Changed delta (history append): a real `Runner.run` probe with a handoff and a tool call over two turns keeps `user, function_call, function_call_output, function_call, function_call_output, message, user, message`, so the handoff turn and the tool outputs survive in order. Two concurrent `invoke` calls keep both turns (`x, assistant, y, assistant`). Passed.
- Tracing opt-out docs line: `OPENAI_AGENTS_DISABLE_TRACING=1` and `agents.set_tracing_disabled(True)` are the SDK's own switches, and the test file already uses the latter. Read in docs/guides/adapters.md, no claim beyond that.
- CI at the head, read once: typecheck, lint, dependency-audit, detection-accuracy, pentest-eval, CodeQL, audit and ci command checks pass. The three `test` jobs, integration-test and Analyze (python) were still pending when I read them, so the full suite and the 85% coverage figure are unmeasured by me; they passed at 24b1f19 and the delta changes only the adapter, one test file, docs and a mypy override.
- `uv lock --check` was started at this head but had not finished before this verdict; pyproject changed only in the mypy overrides (no dependency line), so the lock at 24b1f19 ("Resolved 213 packages", openai-agents 0.20.0 next to crewai) still applies.

## Residual risk
The three test jobs are pending at the head; if one fails, acceptance 6 reopens. The adapter itself behaves on both openai-agents 0.20.0 and 0.25.0.
