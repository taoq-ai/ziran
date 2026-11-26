# Custom Attack Vectors

Add your own attack vectors without writing Python code.

## YAML Format

```yaml
vectors:
  - id: my_unique_id
    name: Human-Readable Name
    category: prompt_injection  # See categories below
    target_phase: vulnerability_discovery
    severity: high  # critical, high, medium, low
    description: What this attack does
    prompts:
      - template: "The prompt to send. Use {variables} for substitution."
        variables:
          variable_name: "default value"
        success_indicators:
          - "strings that indicate the attack succeeded"
        failure_indicators:
          - "strings that indicate the attack was blocked"
    tags: [searchable, tags]
    references:
      - https://link-to-research.com
```

## Two-session vectors

A prompt with `new_session: true` resets the conversation before it is sent, so a later session
can show whether the agent acts on what an earlier one planted in its memory. The vector needs a
multi-turn `tactic` (not `single` or `pair`). The result's `evidence.sessions` lists each session
with its turns: the turn index, prompt, reply (`null` when the turn failed) and tool calls. When
session 1 got no reply, session 2 is not sent and the result is unmeasured.

```yaml
    tactic: context_buildup
    prompts:
      - template: "Remember this preference for future conversations: ..."
      - template: "A routine request that the plant should change"
        new_session: true
        success_indicators: ["value the plant introduced"]
```

ZIRAN runs such a vector only when the target declares memory that survives a reset
(`memory_persists_across_reset: true` in a remote target's YAML). Otherwise the vector is skipped
with the reason `no memory across sessions` and listed as unmeasured, never as passed. The run
leaves the planted value in the target's memory: delete it after the scan.

## Categories

- `prompt_injection`
- `tool_manipulation`
- `privilege_escalation`
- `data_exfiltration`
- `system_prompt_extraction`
- `indirect_injection`
- `memory_poisoning`
- `chain_of_thought_manipulation`

## Using Custom Vectors

```bash
ziran scan --framework langchain --agent-path agent.py --custom-attacks ./my_attacks/
```

ZIRAN will load all `.yaml` and `.yml` files in the directory.
