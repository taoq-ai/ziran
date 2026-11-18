Verdict: PASS
Gate: quality
Item: G5-MCP-SEND-UNMEASURED
PR: taoq-ai/ziran#524
Head: 6963fdd672cf84c9a1391398b05a53c952f88aa9
Confidence: medium

## Findings
- [low] ziran/domain/replies.py:19 blocks: no. Untested: `.strip()` in the exact no-chat match; dropping it (mutant N1d) leaves every touched test green. The handler returns the exact constant, so a padded placeholder needs an adapter that pads it; add a one-line case with surrounding whitespace.
- [low] tests/unit/test_protocol_handlers.py:380 blocks: no. Note: the user-info mutant that uses httpx `.netloc` survives because httpx's netloc already omits user-info, so it is equivalent, not a gap; the mutants that append user-info, a port or the full URL are all killed.

## Probes
- Fresh `git archive 6963fdd` copy, PYTHONPATH pinned, every run under `timeout 120`. attack_executor.py is 384 lines.
- Touched and neighbouring files (test_protocol_handlers, tests/unit/application including test_scanner_size, test_mcp_no_chat_scan, test_tactics, test_scanner, test_mcp_hostile_server): 362 passed at the head; the wider set at 7f0bec4 (adding test_mcp_server_surface, test_incremental_scan, langchain/crewai adapters, test_reserved_metadata, test_many_shot_scan): 450 passed. ruff check, ruff format --check clean; mypy clean on the 4 touched source files.
- Re-exports: `ziran.application.agent_scanner._is_error_response`, `agent_scanner.scanner._is_error_response` and `_ERROR_SENTINELS` and `attack_executor._is_error_response` are the same object; the importers in test_scanner.py and test_attack_executor.py pass.
- Mutants on the final head or the equivalent code at 7f0bec4 (the delta is test-only), fresh copy each: the substring match (killed by the quoted-sentinel tests), the always-False match, dropping the no-chat clause from is_error_response, the executor rule removed or widened, the tactics rule removed, widened to any prompt_errors (M3b, killed by test_a_measured_prompt_keeps_the_vector_measured[crescendo]), evaluated never incremented (M3d, same test), the tactics check removed, the tactics check widened to iteration-limit text, warn-once removed, flag never set, sampling send restored, the result_builder metadata write removed, log full URL, log exception text: all killed. Only N1d survived (the low note above).
- Delta test (records[0].args[0] == "mcp.example.com"): the log-credentials mutants (user-info plus host, host plus port, full URL, host plus query) all fail test_send_fallback_no_completion, so the test still fails if the logged host leaks credentials.
- closed: block on attack_executor.py size at 7f0bec4 (384 lines, test_scanner_size passes). closed: M3b and M3d survivors at 7f0bec4. closed: private-helper import in tactics at 7f0bec4 (now `ziran.domain.replies`, no cycle). closed: scope note, the multi-turn executor only treats the exact placeholder as an error again, so an iteration-limit reply is evaluated as before.
- `gh pr checks 524` read once at this head: lint, typecheck, CodeQL, ci command gate and the audit jobs, dependency-audit, frontend-build and the pentest and detection gates pass; test (3.11/3.12/3.13) and integration-test pending.
- Simplicity: none to delete; the domain module replaces the cross-package private import and holds one constant and two predicates.

## Residual risk
The CI test jobs were still pending at review time; I reproduced them locally for the touched and neighbouring files only. The timeout-as-unmeasured scope of the single-prompt executor stays a documented behaviour change.
