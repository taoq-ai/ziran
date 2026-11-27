# 130 SARIF goal state

Promise: SARIF carries every goal vector's type, state (met, not met, unmeasured) and evidence calls in `runs[0].properties.ziran.goals`, and in `properties.goal` on results already listed; `ziran ci` reads them back, so `fail_on_goal_met` works on a SARIF input. A SARIF without `goals` (older ziran) is still refused with the same message.

Acceptance: given a SARIF from a scan with a met goal, `ziran ci` with `fail_on_goal_met` exits 1 naming the goal.

Design: no extra results, so code scanning and older readers see the same findings as before. Each goals entry names its `result` index when listed (the reader folds the goal into that attack, a needs-review one included) or null (the reader adds a non-successful attack). Every printed string goes through `printable` with `soft_wrap=True`; SARIF strings stay JSON escaped.

Status: Active
