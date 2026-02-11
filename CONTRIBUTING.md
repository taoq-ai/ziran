# Contributing to ZIRAN

Thank you for your interest in contributing to ZIRAN! This guide will help you get started.

## Getting Started

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager

### Setup

```bash
git clone https://github.com/taoq-ai/ziran.git
cd ziran
uv sync --group dev
```

### Running Tests

```bash
uv run pytest                                    # Run all tests
uv run pytest --cov=ziran --cov-report=term       # With coverage
uv run pytest tests/unit/                        # Unit tests only
uv run pytest -k "test_chain"                    # Run specific tests
```

### Linting

```bash
uv run ruff check .        # Lint
uv run ruff format .       # Format
uv run mypy ziran/          # Type check
```

## Ways to Contribute

### 🐛 Bug Reports

Found a bug? [Open an issue](https://github.com/taoq-ai/ziran/issues/new?template=bug_report.md) with:
- Steps to reproduce
- Expected vs actual behaviour
- Environment details

### 💡 Feature Requests

Have an idea? [Open a feature request](https://github.com/taoq-ai/ziran/issues/new?template=feature_request.md).

### ⚔️ Attack Vectors

Add new attack vectors by creating YAML files:

1. Create a file in `ziran/application/attacks/vectors/`
2. Follow the existing YAML format
3. Include success/failure indicators
4. Add tests
5. Submit a PR

### 🛡️ Skill CVEs

Found a vulnerability in an agent tool?

1. [Open a Skill CVE issue](https://github.com/taoq-ai/ziran/issues/new?template=skill_cve.md)
2. Include tool name, framework, severity, and proof of concept
3. The team will review, assign a CVE ID, and add it to the database

### 🔌 Framework Adapters

Add support for new agent frameworks:

1. Create a new adapter in `ziran/infrastructure/adapters/`
2. Implement `BaseAgentAdapter`
3. Add an optional dependency group in `pyproject.toml`
4. Add tests and documentation
5. Submit a PR

### 📝 Documentation

- Fix typos and improve clarity
- Add examples and guides
- Improve docstrings

## Development Workflow

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```
3. **Make changes** and add tests
4. **Ensure all checks pass**:
   ```bash
   uv run pytest
   uv run ruff check .
   uv run ruff format --check .
   uv run mypy ziran/
   ```
5. **Commit** with a clear message
6. **Push** to your fork
7. **Open a Pull Request** against `main`

## Code Style

- Follow existing patterns in the codebase
- Use type hints everywhere
- Write docstrings for public APIs (Google style)
- Keep functions focused and small
- Prefer composition over inheritance

## Commit Messages

```
type: short description

Longer explanation if needed.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

## Code of Conduct

Be respectful, inclusive, and constructive. We're building something to make AI safer — let's do it together.

## Questions?

- Open a [GitHub Discussion](https://github.com/taoq-ai/ziran/discussions)
- Email: leone@taoq.ai

---

Thank you for helping make AI agents safer! 🧘
