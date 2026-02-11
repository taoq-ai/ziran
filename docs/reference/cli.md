# CLI Reference

## Commands

### `ziran scan`

Run a security scan campaign against an AI agent.

```
ziran scan [OPTIONS]
```

| Option | Required | Description |
|--------|----------|-------------|
| `--framework` | Yes | Agent framework: `langchain`, `crewai`, `bedrock` |
| `--agent-path` | Yes | Path to agent code/config file |
| `--phases` | No | Specific phases to run (default: all core phases) |
| `--output`, `-o` | No | Output directory (default: `ziran_results`) |
| `--custom-attacks` | No | Directory with custom YAML attack vectors |
| `--stop-on-critical` | No | Stop if critical vulnerability found (default: true) |

### `ziran discover`

Discover agent capabilities without running attacks.

```
ziran discover --framework FRAMEWORK AGENT_PATH
```

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
| `--custom-attacks` | Include custom YAML vectors |

### `ziran report`

Regenerate a report from a saved campaign result.

```
ziran report RESULT_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--format` | Output format: `terminal`, `markdown`, `json`, `html` |

## Global Options

| Option | Description |
|--------|-------------|
| `--verbose`, `-v` | Enable debug logging |
| `--log-file` | Write logs to file |
| `--version` | Show version |
| `--help` | Show help |
