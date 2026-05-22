# Implementation Plan: ziran init Scaffolding Command

**Branch**: `014-init-scaffolding` | **Date**: 2026-05-22 | **Spec**: [spec.md](spec.md)

## Summary

Add a `ziran init` CLI command that interactively generates a starter `ziran.yaml` configuration file. Uses click prompts for target type and framework selection, with overwrite protection and a `--non-interactive` flag for CI.

## Technical Context

**Language/Version**: Python 3.11+ (CI matrix: 3.11, 3.12, 3.13)
**Primary Dependencies**: click (CLI), rich (output), PyYAML (YAML writing) — all existing
**Storage**: Local filesystem (writes `ziran.yaml` to CWD)
**Testing**: pytest with `click.testing.CliRunner`
**Project Type**: CLI command addition
**Constraints**: No new dependencies. Single file addition + CLI registration.

## Constitution Check

| Gate | Status |
|------|--------|
| Hexagonal Architecture | PASS — CLI command in `interfaces/cli/`, no domain changes |
| Type Safety | PASS — fully typed click command |
| Test Coverage | PASS — CliRunner tests for all paths |
| Simplicity | PASS — single command, no new abstractions |

## Design

### New file: `ziran/interfaces/cli/init_command.py`

Contains the `init` command implementation:
- `_generate_config()` — builds config dict based on user choices
- `_write_config()` — writes YAML with comments
- `init` click command — orchestrates prompts, overwrite check, generation, next-steps panel

### Modified file: `ziran/interfaces/cli/main.py`

Register the init command:
```python
from ziran.interfaces.cli.init_command import init
cli.add_command(init)
```

### Config templates

Two config shapes based on target type:

**In-process** (framework-based):
```yaml
# ZIRAN Configuration
framework: langchain
agent_path: ./my_agent.py
coverage: standard
output_dir: ./ziran-results
phases: [reconnaissance, trust_building, ...]
```

**Remote** (target-based):
```yaml
# ZIRAN Configuration
target: ./target.yaml
coverage: standard
output_dir: ./ziran-results
phases: [reconnaissance, trust_building, ...]
```

### Test file: `tests/unit/test_cli_init.py`

Uses `click.testing.CliRunner` with `mix_stderr=False`:
- Interactive flow (simulated input)
- Overwrite protection (confirm/decline)
- Non-interactive mode
- Generated YAML validation
