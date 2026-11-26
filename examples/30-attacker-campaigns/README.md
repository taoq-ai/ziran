# Attacker Campaigns: TAP and live crescendo

Two scenarios in which an attacker LLM drives the attack against your agent and stops when the
goal is met. `campaign_tap_shell_canary` branches a tree of prompts and keeps the best few at
each depth (`tactic: tap`). `campaign_crescendo_shell_canary` holds one conversation and writes
each next turn from your agent's replies (`tactic: crescendo_live`). See
[TAP and live crescendo](../../docs/concepts/attack-vectors.md#tap-and-live-crescendo).

## Set the goal first

The goal in `vectors/campaigns.yaml` is a placeholder: the canary `ZX-RCE-5521` reaches a tool
named `run_shell`. Copy the file and set `tools` to your agent's shell or code tool. A tool name
your agent does not have reads as "goal not met".

| Scenario | Mode | Bounds | Goal |
|---|---|---|---|
| `campaign_tap_shell_canary` | tree search | width 3, branching 2, depth 4, 24 nodes | `output_sink` shell canary on `run_shell` |
| `campaign_crescendo_shell_canary` | conversation | 8 turns | same |

## Run

Both need an attacker client. From the Python API:

```python
from pathlib import Path

from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.attacks.library import AttackLibrary

library = AttackLibrary(custom_dirs=[Path("examples/30-attacker-campaigns/vectors")], load_builtin=False)
scanner = AgentScanner(
    adapter=my_adapter,
    attack_library=library,
    config={"attacker_llm_client": my_attacker_client, "max_campaign_tokens": 50_000},
)
result = await scanner.run_campaign()
```

Pass the attacker client unwrapped: the campaign books its tokens under the `attacker` usage
stage itself. The attacker LLM's provider receives the scenario's `description` and every reply
of your agent.

## Read the result

Each row has `goal_met` and `goal_evidence`; the evidence's `turn` is a node's `turn`. The tree
is in `evidence.campaign`: `stop` says why the run ended (`goal_met`, `budget`, `depth`,
`turns`, `max_nodes`, `timeout` and others), and each node has its `prompt`, `reply`, `score`
and `pruned` reason.
