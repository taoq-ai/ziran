# 130 SARIF goal state

Promise: SARIF results carry goal type, state (met, not met, unmeasured) and the evidence calls in `properties.goal`; `ziran ci` reads them back, so `fail_on_goal_met` works on a SARIF input. A SARIF written before this (no `runs[0].properties.ziran.goals`) is still refused with the same message.

Acceptance: given a SARIF from a scan with a met goal, `ziran ci` with `fail_on_goal_met` exits 1 naming the goal.

Design: a goal vector that is not a finding is listed with `properties.goal_only` (level the severity when met, `note` otherwise), so not met and unmeasured states survive the round trip. Evidence is the raw call list; every printed string goes through `printable` with `soft_wrap=True`, and SARIF strings stay JSON escaped.

Status: Active
