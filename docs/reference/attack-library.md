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
| `document_carriers.yaml` | 9 | PDF, DOCX, HTML and PNG files with hidden injections (opt-in, `--carriers`) |

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

#### Document and image carriers

The vectors in `document_carriers.yaml` build a real file with the standard library and hide the
instruction in it:

| Format | `placement: body` | `placement: metadata` |
|--------|-------------------|-----------------------|
| PDF | white 1-point text | Info dictionary `Subject` |
| DOCX | white 1-point run | core properties `description` |
| HTML | off-screen block (`left:-9999px`) | `description` meta tag |
| PNG | faint grey rendered text | `tEXt` chunk `Description` |

The scan delivers the file where the agent reads it. `delivery: workspace`, `knowledge_base`
and `page` write it (under a random suffix, never over an existing file) into a folder from the
`--carriers` file, and remove it when the vector ends; the prompt names it through `{carrier}`.
`delivery: attachment` sends it with the message: the Anthropic adapter takes PNG and PDF, and
the HTTP adapter takes PNG on the `openai` protocol. Other adapters send text only.

```yaml
# carriers.yaml, for `ziran scan --carriers carriers.yaml`
workspace_dir: /srv/agent/workspace     # read by the agent's file tools
knowledge_base_dir: /srv/agent/kb-inbox # ingested by its knowledge base
page_dir: /var/www/test-pages           # served at page_url
page_url: https://pages.internal.example/
```

A finding needs the hidden text's canary or address in a tool call's arguments, as for every
vector. A vector the scan cannot deliver (no folder, or an adapter that takes no attachment of
that type) is skipped with its reason and reads unmeasured, never as a pass. Without
`--carriers` the scan leaves these vectors out; an empty file runs the attachment vectors only.

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
