# Analysis: attacker-LLM campaigns (TAP tree search, live crescendo)

Spec, plan and tasks read against each other and against the plan item F-ATTACKER-LOOP.

| ID | Severity | Where | Finding | Status |
| --- | --- | --- | --- | --- |
| A01 | MEDIUM | spec Assumptions, FR-001 | Until F-SCAN-ATTACKER-FLAG lands, a `tap` or `crescendo_live` vector without an attacker client is an error row, as `pair` is today, not a dropped and listed vector. No such vector ships in the built-in library, so none runs unconfigured by default; the flag's drop reads `is_pair`, which covers both tactics (tested). | Open, closes with F-SCAN-ATTACKER-FLAG |
| A02 | MEDIUM | spec Clarifications | TAP does not reset the target between nodes, so on a stateful agent a node's reply can depend on earlier siblings. A reset would cut another vector's conversation on a shared adapter. | Recorded in the docs |
| A03 | LOW | spec Assumptions | The cassette repeat runs through `RecordReplayClient` with a few test lines that pass the system text as the key's prompt; there is no CLI cassette option. | Recorded, a candidate beside `--attacker-model` |
| A04 | LOW | item acceptance 1 | The item names an RCE agent that this repository does not hold; the acceptance test uses the example scenario `campaign_tap_shell_canary` against a scripted shell agent. | Closed |
| A05 | LOW | item promise | The promise names GOAT or a live crescendo for the conversation mode; `crescendo_live` is built, GOAT's technique library is out of scope. | Recorded in Out of scope |
| A06 | LOW | tasks T008 | The first mutant run left the rank order alive: every tie held equal scores. A test with unequal scores at depth 3 now kills both the reversed and the missing sort. | Closed |
| A07 | LOW | plan step 5 | `attack_executor.py` dispatch shares a line with F-SCAN-ATTACKER-FLAG (`self._attacker` renamed `attacker`). Whichever merges second keeps both changes. | Recorded in the PR |
| A08 | LOW | coverage | Every FR has a task and a test; FR-010 is held by `test_scanner_size.py` and the diff stat. | Closed |
| A09 | HIGH | goal gate round 1, `campaign.py` budget check | The check before each node read the ledger only, and the phase books target tokens when the vector ends, so TAP ran 1,000,000 target tokens on a 50,000 cap. PAIR had the same gap. | Closed: FR-005, T010, tested for TAP, crescendo_live, PAIR and a scan |
| A10 | HIGH | security gate round 1, `pair.py` `_parse_prompt` | A reply with a 4,300-digit integer or about 1,000 nested brackets (3.11) raised past the loop, so the vector was dropped with its tree, an earlier success and its tokens. | Closed: FR-006, T011, tested on 3.11, 3.12, 3.13 |
| A11 | MEDIUM | security gate round 1, `campaign.py` result | A run cut short by the attacker provider or the budget read as resisted. | Closed: FR-005, T012 |
| A12 | LOW | security gate round 1, `attack.py` | `timeout_seconds` took inf and 1e308, so the phase timer could be infinite. | Closed: FR-002, T012 |
| A13 | LOW | arch gate round 1, docs | The node count said 24 with the defaults; the most is 18. | Closed: T012 |

No CRITICAL or HIGH row is open.
