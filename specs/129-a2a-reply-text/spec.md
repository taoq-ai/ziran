# 129 A2A reply text

Promise: A2A task artifact data parts are recorded as reply text (JSON, non-ASCII kept), and a status message from the user never enters the reply text (role ROLE_USER, user, or absent), each pinned by a test through HttpAgentAdapter.

Acceptance: an artifact {min_price: 800} with secret 800 gives goal_met true; a user-role status message holding 800 is not a leak.

Status: Active
