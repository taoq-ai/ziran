# Analysis: adversarial counterpart scenarios for negotiating agents

Spec, plan and tasks read against each other and against the plan item F-NEGOTIATION-ADVERSARY.

| ID | Severity | Where | Finding | Status |
| --- | --- | --- | --- | --- |
| A01 | MEDIUM | spec Out of scope | `goal_met` shows in the JSON `attack_results` rows only; the Markdown and HTML reports do not render it (as in spec 116). A breach reads `successful: false` there. | Open, a candidate item |
| A02 | LOW | spec Assumptions | The item's variance check (10 runs on 2 models) needs live keys; not run. | Unmeasured, recorded |
| A03 | LOW | spec FR-003 | A PAIR attacker may guess the secret and the target may echo it; the echo counts as a leak. Scripted prompts cannot hold it (FR-004). | Recorded in the docs |
| A04 | LOW | tasks T001 | The red run was taken against the base source (`git stash` of `ziran/`): collection fails on the missing `Replies` import. | Closed |
| A05 | LOW | plan step 4 | Every FR has a task and a test; FR-008 is held by `test_scanner_size.py` and the diff stat. | Closed |

No CRITICAL or HIGH row is open.
