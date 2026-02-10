# Attack Library Reference

Complete list of built-in attack vectors.

## Categories

### Prompt Injection (`prompt_injection`)
Attempts to override or bypass agent instructions.

### Tool Manipulation (`tool_manipulation`)
Exploits agent tool usage patterns.

### Privilege Escalation (`privilege_escalation`)
Attempts to gain unauthorized access.

### Data Exfiltration (`data_exfiltration`)
Extracts sensitive information.

### System Prompt Extraction (`system_prompt_extraction`)
Leaks system prompt contents.

### Indirect Injection (`indirect_injection`)
Injects via external data sources.

### Memory Poisoning (`memory_poisoning`)
Plants persistent malicious instructions.

### Chain-of-Thought Manipulation (`chain_of_thought_manipulation`)
Hijacks agent reasoning.

## Listing Vectors

```bash
koan library --list
koan library --category prompt_injection
koan library --phase reconnaissance
```

## Vector Severity Levels

| Level | Description |
|-------|-------------|
| `critical` | Can lead to RCE, full data access, or complete agent compromise |
| `high` | Significant data leakage, tool misuse, or privilege escalation |
| `medium` | Partial information disclosure or boundary bypass |
| `low` | Minor information leakage or configuration exposure |
