# 131 Shared running-token counter

Promise: CampaignBudget tracks running target tokens across concurrent attacker vectors, so a campaign stops within one reply per vector of the cap at any concurrency.

Acceptance: 3 and 5 concurrent TAP (and PAIR) vectors on a 50,000 cap with a target spending 5,000 per reply spend at most the cap plus one reply per vector; the ledger total equals the rows' token_usage (booked once).

Status: Active

Design: `CampaignBudget.running` is added to by each attacker loop on every target reply and released by `TrialRunner` in the same step that books the vector's tokens to the ledger (no await between), so a check never sees tokens twice or not at all. A loop that is cancelled or raises releases its own tokens. `exceeded()` no longer takes a per-vector argument.

Assumptions: the phase books only executed attacker results (a cache hit adds nothing and releases nothing); a loop ending normally leaves release to the runner.
