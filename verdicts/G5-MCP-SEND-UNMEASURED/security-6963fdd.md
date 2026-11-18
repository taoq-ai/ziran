Verdict: PASS
Gate: security
Item: G5-MCP-SEND-UNMEASURED
PR: taoq-ai/ziran#524
Head: 6963fdd672cf84c9a1391398b05a53c952f88aa9
Confidence: high

## Findings
- [low] ziran/domain/replies.py:20 blocks: no. On every protocol, a reply whose text is exactly the placeholder after strip is dropped before the detectors, along with any tool_calls it carries, so an agent that replied with that exact string while calling a dangerous tool would read unmeasured (INCOMPLETE) rather than vulnerable. This is contrived and shows visibly; it is the same class as develop's iteration-limit substring. Gating on `metadata["protocol"] == "mcp"` would close it
- [low] ziran/application/cicd/gate.py:127 blocks: no. Existing spec-071 policy, out of scope: `ziran ci` fails only when every vector is unmeasured, so a scan with some unmeasured vectors reads INCOMPLETE but can pass the gate

## Probes
Delta 7f0bec4..6963fdd is test-only: tests/unit/test_protocol_handlers.py (+5/-3). `diff -rq` of the ziran/ trees at 7f0bec4 and 6963fdd shows them identical. The new assertion pins `records[0].args[0] == "mcp.example.com"`. Mutant M8 (log the full normalized_url) still fails test_send_fallback_no_completion at 6963fdd.
Touched tests at 6963fdd (protocol_handlers, attack_executor, mcp_no_chat_scan integration, test_tactics): 82 passed.
probe.py ran against git-archive copies of 7f0bec4 and 6963fdd with PYTHONPATH pinned (ziran.__file__ was checked to resolve to the copy) and timeout 120, compared with develop eaf2ee5.
Two-prompt case (vulnerable reply plus phrase, then a refusal): successful=True, the same as develop.
Crescendo with a vulnerable reply plus the placeholder: successful=True, the same as develop.
No-chat server: only completion/complete is called, outcome=unmeasured, prompt_errors=1, cacheable=False. On develop it also sent sampling/createMessage and the vector was cacheable as resisted.
probe2.py placeholder variants, single and crescendo. The exact placeholder, and the placeholder padded with whitespace or newlines, read unmeasured and uncached. Lowercase, hyphen for the em dash, NBSP, a zero-width prefix and a trailing dot all go to the detectors, exactly as on develop, which is the safe direction. A vulnerable reply plus the exact placeholder stays successful in both paths. "Agent stopped due to iteration limit" plus a vulnerable reply stays successful in crescendo, as on develop. In single-turn it is dropped as on develop, now also marked unmeasured, which is more visible.
Log redaction: with URL `https://user:pw@mcp.example.com/?api_key=QSECRET` and server error text "nope\nFAKE ... sk-LEAKED", the warning is a single line, `MCP server mcp.example.com took no chat prompt (completion/complete failed: ProtocolError, HTTP None)`. It carries no userinfo, query token, newline or server text.
Mutants at 7f0bec4, a fresh git-archive copy each (mutants2.sh); all 10 were killed:
- M1 is_no_chat_reply returns False: 6 tests failed.
- M2 substring match restored: 2 failed (a reply quoting the placeholder is still scored, single and crescendo).
- M3 unmeasured guard reversed: 3 failed.
- M4 tactic check off: 2 failed.
- M5 tactics using all sentinels: 1 failed (crescendo with the iteration-limit phrase).
- M6 tactic outcome off: 1 failed.
- M7 warning on every send: 2 failed.
- M8 log the full URL: 1 failed.
- M9 log the exception text: 1 failed.
- M10 result-builder filter off: 1 failed.
closed: attack_executor.py:48 substring sentinel hides a partial compromise at 7f0bec4
closed: tactics.py:133 substring sentinels in tactics at 7f0bec4
closed: mcp_handler.py:69 warning logs URL and server text at 7f0bec4
createMessage and the cache were re-checked: the ziran/ code is unchanged from b252b75 on both points. No client path sends sampling/createMessage, and every unmeasured result carries prompt_errors or no agent_response, so is_cacheable is False.
Scanner: no dependency, lockfile or workflow change. The repo's pip-audit step was not run locally, so it is unmeasured here.
Confidence high: every case was compared head against develop with the real detector pipeline, and every guard mutant was killed.

## Residual risk
A target can still steer its own score by behaving differently under a scan, and that is inherent. Develop's substring match on the LangChain phrases in single-turn stays as it was.
