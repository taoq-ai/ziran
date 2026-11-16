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

## Licensing and the Contributor License Agreement

ZIRAN is source-available under the [Functional Source License 1.1, Apache-2.0 future licence](LICENSE) (`FSL-1.1-ALv2`). Releases up to and including v0.42.0 stay under Apache-2.0; see [NOTICE](NOTICE).

TaoQ AI offers ZIRAN under FSL and under separate commercial licences, so every contribution needs the agreement below. To accept it, add this line to your pull request description:

> I have read and agree to the ZIRAN Contributor License Agreement in CONTRIBUTING.md.

A pull request without that line is not merged.

### ZIRAN Contributor License Agreement

"You" means the person or legal entity submitting a Contribution. "Contribution" means any code, documentation or other material you submit to TaoQ AI for inclusion in ZIRAN, through a pull request, issue, patch or otherwise. "TaoQ AI" means the maintainer of ZIRAN and its successors and assigns.

1. **Copyright licence.** You grant TaoQ AI and recipients of software it distributes a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable licence to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense and distribute your Contributions and such derivative works, under any licence terms TaoQ AI chooses, including the FSL, Apache-2.0 and proprietary commercial licences.
2. **Patent licence.** You grant TaoQ AI and recipients of software it distributes a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable patent licence to make, have made, use, offer to sell, sell, import and otherwise transfer your Contributions, for the patent claims you can license that your Contribution alone, or its combination with ZIRAN, necessarily infringes.
3. **You keep your rights.** You keep the copyright in your Contributions. This agreement is a licence, not an assignment, and you may use your Contributions in any other way you like.
4. **Your representations.** Each Contribution is your original work, or you have the right to submit it under this agreement, and you name any third-party material and its licence in the pull request. If your employer has rights in what you create, you have its permission to make the Contribution, or it has waived those rights.
5. **No warranty.** Unless you agree otherwise in writing, you provide your Contributions "as is", without warranties or conditions of any kind.

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

## Branching Model

This project uses **Git Flow**:

- **`main`** — production branch, always releasable. Only receives merges from `release/*` and `hotfix/*` branches.
- **`develop`** — integration branch. All feature PRs target `develop`.
- **`feat/*`, `fix/*`, `docs/*`** — branch from `develop`, PR back to `develop`.
- **`release/vX.Y.Z`** — cut from `develop` when ready for release. Only bugfixes allowed. Merged to both `main` and `develop`.
- **`hotfix/*`** — emergency fixes branched from `main`, merged to both `main` and `develop`.

## Development Workflow

1. **Fork** the repository
2. **Create a branch** from `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feat/my-feature
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
7. **Open a Pull Request** against `develop`

### Creating a release

```bash
git checkout develop && git pull origin develop
git checkout -b release/v0.31.0
# Only bugfixes allowed on this branch
# Open PR targeting main
# After merge to main, also merge release/v0.31.0 into develop
```

### Hotfixes

```bash
git checkout main && git pull origin main
git checkout -b hotfix/critical-fix
# Open PR targeting main
# After merge, also merge hotfix/critical-fix into develop
```

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
