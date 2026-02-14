# CLI Reference

ZIRAN provides 7 commands for scanning, reporting, and CI/CD integration.

## Global Options

| Option | Description |
|--------|-------------|
| `--verbose`, `-v` | Enable debug logging |
| `--log-file PATH` | Write logs to file |
| `--version` | Show version |
| `--help` | Show help |

## Commands

### `ziran scan`

Run a security scan campaign against an AI agent.

```
ziran scan [OPTIONS]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--framework` | Yes\* | — | Agent framework: `langchain`, `crewai`, `bedrock` |
| `--agent-path` | Yes\* | — | Path to agent code/config file |
| `--target` | Yes\* | — | YAML target config for remote scanning |
| `--protocol` | No | `auto` | Protocol override: `rest`, `openai`, `mcp`, `a2a`, `auto` |
| `--phases` | No | all core | Specific phases to run |
| `--coverage` | No | `standard` | Coverage level: `essential`, `standard`, `comprehensive` |
| `--output`, `-o` | No | `ziran_results` | Output directory |
| `--custom-attacks` | No | — | Directory with custom YAML attack vectors |
| `--stop-on-critical` | No | `true` | Stop if critical vulnerability found |
| `--concurrency` | No | `5` | Max concurrent attacks |

\* Either `--framework` + `--agent-path` (local) or `--target` (remote) is required.

**Examples:**

```bash
# Local agent
ziran scan --framework langchain --agent-path agent.py

# Remote agent
ziran scan --target target.yaml

# Full audit with custom vectors
ziran scan --target target.yaml --coverage comprehensive \
  --custom-attacks ./my_attacks/ --concurrency 10
```

---

### `ziran discover`

Discover agent capabilities without running attacks (Phase 1 only).

```
ziran discover [OPTIONS] [AGENT_PATH]
```

| Option | Description |
|--------|-------------|
| `--framework` | Agent framework: `langchain`, `crewai`, `bedrock` |
| `--target` | YAML target config for remote discovery |
| `--protocol` | Protocol override |

**Examples:**

```bash
ziran discover --framework langchain agent.py
ziran discover --target target.yaml
```

---

### `ziran library`

Browse the attack vector library.

```
ziran library [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--list` | List all attack vectors |
| `--category` | Filter by category |
| `--phase` | Filter by target phase |
| `--owasp` | Filter by OWASP LLM category (`LLM01`–`LLM10`) |
| `--custom-attacks` | Include custom YAML vectors |

**Examples:**

```bash
ziran library --list
ziran library --category prompt_injection
ziran library --owasp LLM01
ziran library --phase vulnerability_discovery
```

---

### `ziran report`

Regenerate a report from a saved campaign result.

```
ziran report RESULT_FILE [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal`, `markdown`, `json`, `html` |

**Examples:**

```bash
ziran report results.json --format html
ziran report results.json --format markdown
```

---

### `ziran poc`

Generate proof-of-concept exploits from scan results.

```
ziran poc RESULT_FILE [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--output`, `-o` | `.` | Output directory |
| `--format` | `all` | PoC format: `python`, `curl`, `markdown`, `all` |

**Examples:**

```bash
ziran poc results.json --format python --output ./pocs/
ziran poc results.json --format curl
```

---

### `ziran policy`

Evaluate scan results against a policy file.

```
ziran policy RESULT_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--policy`, `-p` | Path to YAML policy file |

**Example:**

```bash
ziran policy results.json --policy production-policy.yaml
```

---

### `ziran audit`

Run static analysis on agent source code (no LLM required).

```
ziran audit PATH [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--severity` | Minimum severity filter: `critical`, `high`, `medium`, `low` |

**Examples:**

```bash
ziran audit my_agent.py
ziran audit ./src/agents/ --severity high
```

---

### `ziran ci`

CI/CD quality gate — evaluate results and emit integration outputs.

```
ziran ci RESULT_FILE [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--gate-config`, `-g` | — | Quality gate YAML config |
| `--policy`, `-p` | — | Policy file for rule evaluation |
| `--sarif` | — | Write SARIF v2.1.0 report to path |
| `--github-annotations` | `true` | Emit GitHub Actions annotations |
| `--github-summary` | `true` | Write GitHub Actions step summary |

**Examples:**

```bash
# Simple gate check
ziran ci results.json --gate-config gate.yaml

# Full CI pipeline
ziran ci results.json \
  --gate-config gate.yaml \
  --policy policy.yaml \
  --sarif results.sarif \
  --github-annotations \
  --github-summary
```
