# Attack Library Reference

ZIRAN ships with **137 attack vectors** across **9 YAML files** and **8 categories**, with OWASP LLM Top 10 mapping.

## Vector Files

| File | Vectors | Description |
|------|---------|-------------|
| `prompt_injection.yaml` | 18 | Direct instruction override, role-play, multi-turn |
| `data_exfiltration.yaml` | 16 | PII leaks, file reads, database dumps |
| `system_prompt_extraction.yaml` | 16 | System prompt leaking, instruction disclosure |
| `tool_manipulation.yaml` | 16 | Tool misuse, malicious parameters, chaining |
| `chain_of_thought_manipulation.yaml` | 15 | Reasoning hijack, decision manipulation |
| `indirect_injection.yaml` | 15 | Injection via documents, search results, RAG |
| `memory_poisoning.yaml` | 15 | Persistent instruction planting |
| `privilege_escalation.yaml` | 15 | Admin impersonation, scope widening |
| `a2a_attacks.yaml` | 11 | A2A protocol-specific attacks |

## Categories

### Prompt Injection (`prompt_injection`)
Attempts to override or bypass agent instructions — simple overrides, role-play, multi-turn escalation, encoding tricks.

### Tool Manipulation (`tool_manipulation`)
Exploits agent tool usage — malicious parameters, unintended sequences, adversarial payloads, tool confusion.

### Privilege Escalation (`privilege_escalation`)
Gains unauthorized access — admin impersonation, scope widening, OAuth abuse, hidden capability probing.

### Data Exfiltration (`data_exfiltration`)
Extracts sensitive information — file reads, database dumps, PII leaks, credential harvesting.

### System Prompt Extraction (`system_prompt_extraction`)
Leaks system prompt contents — direct requests, encoding tricks, prompt reconstruction, instruction disclosure.

### Indirect Injection (`indirect_injection`)
Injects via external data sources — document poisoning, search result manipulation, RAG context injection.

### Memory Poisoning (`memory_poisoning`)
Plants persistent malicious instructions — cross-session attacks, memory slot manipulation, delayed execution.

### Chain-of-Thought Manipulation (`chain_of_thought_manipulation`)
Hijacks agent reasoning — tool selection manipulation, execution order changes, confidence manipulation.

## OWASP Mapping

| OWASP Code | Category | Vectors |
|------------|----------|---------|
| LLM01 | Prompt Injection | 52 |
| LLM06 | Sensitive Information Disclosure | 51 |
| LLM02 | Insecure Output Handling | 20 |
| LLM07 | Insecure Plugin Design | 20 |
| LLM08 | Excessive Agency | 18 |
| LLM03 | Training Data Poisoning | 15 |
| LLM09 | Overreliance | 15 |

## Listing Vectors

```bash
# All vectors
ziran library --list

# By category
ziran library --category prompt_injection

# By OWASP category
ziran library --owasp LLM01

# By target phase
ziran library --phase reconnaissance

# Including custom vectors
ziran library --list --custom-attacks ./my_vectors/
```

## Severity Levels

| Level | Meaning | Example |
|-------|---------|---------|
| `critical` | Full agent compromise, RCE, complete data access | System prompt extraction with tool list |
| `high` | Significant data leakage, tool misuse, privilege escalation | PII extraction via tool chain |
| `medium` | Partial information disclosure, boundary bypass | Partial system prompt leak |
| `low` | Minor information leakage, configuration exposure | Error message verbosity |

## Adding Custom Vectors

See the [YAML format documentation](../concepts/attack-vectors.md) for details on writing custom vectors.
