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
