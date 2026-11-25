# Analysis: the study-v2.1 detector changes

Spec, plan and tasks read against each other and against the design at `711b84c`, at the head that holds changes 1, 9, 2, 4 and 6.

| ID | Severity | Where | Finding | Status |
| --- | --- | --- | --- | --- |
| A01 | MEDIUM | spec FR-005, tasks T008 | Change 3 is specified and not built. The design leaves four points open on how the unchanged paper script sees its effect (the handback lists them). | Open, waits for the design owner |
| A02 | MEDIUM | spec FR-007, task T010 | Change 8 is built against the design's measured effect, not its rule text (spec Assumptions): the literal edit trips the design's stop rule. Its 146 design-half requests are recorded, not sent. | Open: the design owner's ruling on the reading, then the sends |
| A03 | LOW | spec Assumptions | Blast radius and trifecta legs keep the V2 word rules; the design names neither file. | Recorded as an assumption |
| A04 | LOW | plan step 4 | Two patterns on one pair: the plan takes the longest pattern, one of the two options the design allows. | Recorded in the PR |
| A05 | LOW | tasks T011 | The whole suite ran at `b9252d7`: 4,913 passed; the 6 failures and 9 errors are the ones `develop` has in the same environment. | Closed |

No CRITICAL or HIGH row is open.
