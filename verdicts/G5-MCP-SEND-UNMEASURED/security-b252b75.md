Verdict: FIX
Gate: security
Item: G5-MCP-SEND-UNMEASURED
PR: taoq-ai/ziran#524
Head: b252b7552d5eee897ae660f575ca4724af2f15df
Confidence: high

## Findings
- [medium] ziran/application/agent_scanner/attack_executor.py:48 blocks: yes. Failure: the new sentinel is matched as a case-insensitive substring anywhere in a reply (line 59), for every protocol, so a target that answers prompt 1 with "PWNED-INDICATOR sk-... mcp server does not support direct messaging" and refuses prompt 2 has its real compromise dropped. The vector reads not successful with no `outcome: unmeasured`, so the report shows no INCOMPLETE and `ziran ci` passes. On develop (eaf2ee5) the same reply scores successful=True. Fix: match only the handler's exact placeholder (for example `text.strip() == "[MCP server does not support direct messaging — use tools/call]"`), not a substring (CWE-697, CWE-693)
- [medium] ziran/application/attacks/tactics.py:133 blocks: yes. Failure: multi-turn tactics now run the same substring check before the detectors, for all sentinels, so a tactic turn whose vulnerable reply contains the placeholder phrase or "agent stopped due to iteration limit" is no longer scored. On develop it scores successful=True; at head it reads unmeasured, or plain resisted when another indicator turn is answered. Use the exact-placeholder check here as well (CWE-697)
- [low] ziran/infrastructure/adapters/protocols/mcp_handler.py:69 blocks: no. The new warning logs `normalized_url` verbatim (userinfo and query tokens included; the probe logged `https://user:pw@...?api_key=QSECRET`) and the server's JSON-RPC error message verbatim, so a hostile server can forge log lines with a newline (CWE-117, CWE-532). Auth headers are not logged. The pattern already exists (the circuit-breaker message and the executor's `prompt_error` log carry the URL and server error text), but logging only the method and the error code would avoid it
- [low] ziran/application/cicd/gate.py:127 blocks: no. Existing spec-071 policy: `ziran ci` fails only when every vector is unmeasured. A scan where a vulnerable vector is unmeasured and the others are measured reads INCOMPLETE but passes the gate. The docs line describes this accurately. Out of this item's scope
- [low] blocks: no. tests/unit/test_tactics.py has no case for the new tactic sentinel route. Only the crescendo parametrisation in test_attack_executor.py covers it, and it does kill M3/M4

## Probes
Probe script (scratch probes/probe.py) run with a MockTransport MCP server and the real DetectorPipeline against git-archive copies of head b252b75 and develop eaf2ee5, under timeout 120.
known-positive vuln reply, no sentinel: head successful=True, base successful=True (cacheable both).
vuln reply plus placeholder text, one prompt: head successful=False outcome=unmeasured prompt_errors=1 cacheable=False; base successful=True. Visible as INCOMPLETE, but still a lost finding.
partial (prompt 1 vuln plus phrase, prompt 2 refusal): head successful=False outcome=None prompt_errors=1 cacheable=False, so not INCOMPLETE; base successful=True. This is finding 1.
tactic (crescendo) with vuln plus placeholder: head successful=False outcome=unmeasured; base successful=True. This is finding 2.
no-chat server: head methods={completion/complete} only, outcome=unmeasured, prompt_errors=1, cacheable=False; base methods include sampling/createMessage and the vector scored as resisted and cacheable. Known-negative confirmed fixed.
(2) grep -rn createMessage ziran tests benchmarks examples: the only remaining send is ziran/infrastructure/mcp_hostile/server.py (server-to-client, legitimate); the other hits are YAML vector descriptions, docstrings and tests. No client path sends it.
(3) log probe: the warning line contains the configured URL and the server error text, including the injected newline and fake secret. See the low note.
(4) cache: scan_cache.is_cacheable needs no prompt_errors and a non-None agent_response. Every unmeasured path sets prompt_errors>=1 (executor: answered=0<len; tactics: the condition requires prompt_errors), and the zero-prompt case has agent_response=None. The probes report cacheable=False for every unmeasured case, and the integration test asserts there are no cache files.
Mutants (fresh git-archive copy each, touched tests plus test_tactics.py): M1 drop sentinel: 5 failed; M2 reverse `if not answered`: 3 failed; M3 disable tactic sentinel check: 1 failed (crescendo param); M4 disable tactic outcome: 1 failed; M5 warn-every-time: 2 failed (test_send_fallback_no_completion, integration); M6 builder unmeasured filter off: 1 failed (integration). All killed.
Touched tests at head: 62 passed (test_protocol_handlers, test_attack_executor, test_mcp_no_chat_scan).
Circuit breaker: send catches ProtocolError and returns the placeholder, so the adapter records no failure; the integration test asserts CLOSED. A transient 429/5xx on completion/complete is also swallowed into unmeasured. That direction is fail-safe and the behaviour is unchanged from develop.
Scanner: no secret, dependency or SAST change in the diff (no new dependency, lockfile or workflow). The repository's pip-audit/npm-audit CI steps were not run locally and are unmeasured here.
Confidence high: both blocking findings come from a differential head-versus-develop run with the real detector pipeline.

## Residual risk
A target can still steer its own score by refusing during a scan, and that is inherent. Exact-placeholder matching closes the hiding this PR opens. The older sentinels keep their substring match in the single-prompt executor, as before.
