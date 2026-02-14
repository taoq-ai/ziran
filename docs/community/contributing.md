# Contributing to ZIRAN

Thank you for your interest in contributing to ZIRAN! Every contribution matters — from bug reports to new attack vectors.

## Quick Start

```bash
git clone https://github.com/taoq-ai/ziran.git && cd ziran
uv sync --extra all
uv run pytest               # Run tests (428+)
uv run ruff check .         # Lint
uv run mypy ziran/          # Type check
```

## Ways to Contribute

### Report Bugs
[Open an issue](https://github.com/taoq-ai/ziran/issues/new) with steps to reproduce.

### Add Attack Vectors
Create a YAML file in `ziran/application/attacks/vectors/` following the [vector format](../concepts/attack-vectors.md). Each vector needs:

- Unique `id`, `name`, `category`, `target_phase`, `severity`
- OWASP mapping (`owasp_category`)
- At least one prompt with `success_indicators`
- Tests in `tests/`

### Add Framework Adapters
Implement `AgentAdapter` — see [Architecture](../concepts/architecture.md) for the port interfaces.

### Improve Documentation
Docs live in `docs/` and use MkDocs Material. Preview locally:

```bash
uv run mkdocs serve
```

### Add Skill CVEs
See [Skill CVEs](skill-cves.md) for the submission format.

## Development Practices

- **Tests required** — All PRs must include tests and pass CI
- **Type hints** — Use `mypy --strict` compatible annotations
- **Linting** — `ruff check .` must pass (zero errors)
- **Architecture** — Follow hexagonal architecture (domain has no external deps)
- **Commit messages** — Use conventional commits (`feat:`, `fix:`, `docs:`, etc.)

## Full Guide

See [CONTRIBUTING.md](https://github.com/taoq-ai/ziran/blob/main/CONTRIBUTING.md) for the complete contributor guide.
