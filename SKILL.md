# ZIRAN — AI Agent Security Testing Framework

## What is this project?

ZIRAN is an open-source security testing framework for AI agents. It tests agents with tools, memory, and multi-step reasoning — not just LLMs. It runs multi-phase trust exploitation campaigns, analyzes dangerous tool chain combinations, and tracks attack paths via knowledge graphs.

Built by [TaoQ AI](https://www.taoq.ai). Licensed under Apache-2.0.

## Tech stack

- **Language:** Python 3.11+ (tested on 3.11, 3.12, 3.13)
- **Package manager:** [uv](https://docs.astral.sh/uv/)
- **Build system:** hatchling + hatch-vcs (version from git tags)
- **Linter/formatter:** Ruff
- **Type checker:** MyPy (strict mode, with pydantic plugin)
- **Test framework:** pytest + pytest-asyncio + pytest-cov
- **Core libraries:** Pydantic, NetworkX, Click, Rich, httpx, PyYAML

## Architecture

Clean Architecture with Domain-Driven Design:

```
ziran/
├── domain/           # Pure entities (Pydantic models) and interfaces — no infrastructure/framework dependencies
│   ├── entities/     # Data models: attack, phase, capability, target, detection, etc.
│   └── interfaces/   # Abstract base classes: BaseAgentAdapter, detector protocols
├── application/      # Business logic — orchestrators, strategies, detectors
│   ├── agent_scanner/ # Core campaign orchestrator (AgentScanner)
│   ├── attacks/       # Attack library + YAML vector files
│   ├── strategies/    # Campaign execution: fixed, adaptive, llm-adaptive
│   ├── knowledge_graph/ # NetworkX MultiDiGraph + chain analyzer (30+ patterns)
│   ├── detectors/     # Vulnerability detection pipeline
│   ├── pentesting/    # Autonomous pentesting agent (LangGraph-based)
│   ├── cicd/          # CI/CD gate, SARIF output, GitHub Actions integration
│   ├── multi_agent/   # Multi-agent system scanning
│   ├── dynamic_vectors/ # Runtime attack generation
│   ├── poc/           # Proof-of-concept exploit generation
│   ├── policy/        # Policy engine
│   ├── skill_cve/     # CVE knowledge base
│   └── static_analysis/ # Source code analysis
├── infrastructure/   # Technical implementations — adapters, LLM clients, storage
│   ├── adapters/      # Framework adapters: langchain, crewai, bedrock, agentcore, http
│   │   └── protocols/ # Protocol handlers: rest, openai, mcp, a2a, sse, ws
│   ├── llm/           # LiteLLM-based multi-provider LLM client
│   ├── logging/       # Structured logging
│   └── storage/       # JSON-based graph persistence
└── interfaces/       # User-facing layer
    └── cli/           # Click-based CLI (main.py), reports, visualizations
```

## Key commands

```bash
# Setup
uv sync --group dev                  # Install all dev dependencies

# Quality checks
uv run ruff check .                  # Lint
uv run ruff format .                 # Format
uv run ruff format --check .         # Format check (CI)
uv run mypy ziran/                   # Type check (strict)

# Testing
uv run pytest                        # All tests
uv run pytest -m "not integration"   # Unit tests only
uv run pytest -m integration         # Integration tests only
uv run pytest --cov=ziran            # With coverage
uv run pytest -k "test_name"         # Specific test

# Build
uv build                             # Build wheel + sdist
```

## CLI entry point

`ziran = ziran.interfaces.cli.main:cli` — Click command group.

Main commands: `scan`, `discover`, `library`, `report`, `poc`, `policy`, `audit`, `ci`, `multi-agent-scan`, `pentest`.

## Conventions

- **Type hints everywhere** — MyPy strict mode is enforced
- **Pydantic models** for all domain entities
- **Google-style docstrings** for public APIs
- **Composition over inheritance** — adapters implement `BaseAgentAdapter` ABC
- **Ruff rules:** E, W, F, I, N, UP, B, SIM, TCH, RUF (E501 ignored)
- **Line length:** 100 characters
- **Commit style:** `type: short description` — types: feat, fix, docs, test, refactor, chore
- **Coverage gate:** 80% minimum (pyproject.toml), 89% in CI
- **Attack vectors:** YAML files in `ziran/application/attacks/vectors/`
- **Tests mirror source:** `tests/unit/` and `tests/integration/`

## Optional dependency groups

The project has optional extras for framework integrations:

- `langchain` — LangChain agent support
- `crewai` — CrewAI framework support
- `a2a` — Agent-to-Agent protocol
- `bedrock` — AWS Bedrock agents
- `agentcore` — Bedrock AgentCore
- `llm` — LiteLLM multi-provider routing
- `pentest` — Autonomous pentesting agent (includes llm + langgraph + numpy)
- `all` — Everything

Install extras: `pip install ziran[all]` or `uv sync --extra all`

## Key domain concepts

- **Campaign:** A multi-phase security scan (8 phases: reconnaissance through exfiltration)
- **Attack vector:** A YAML-defined prompt template with success/failure indicators and OWASP mapping
- **Knowledge graph:** NetworkX MultiDiGraph tracking tools, data sources, permissions, vulnerabilities, and exploit chains
- **Chain analysis:** Detects dangerous tool compositions (e.g., `read_file` + `http_request` = data exfiltration)
- **Adapter:** Framework-specific integration layer implementing `BaseAgentAdapter`
- **Strategy:** Campaign execution plan (fixed, adaptive, or llm-adaptive)
- **Detection pipeline:** Multi-detector system (indicator-based, LLM judge, refusal detector)

## CI/CD

GitHub Actions workflows in `.github/workflows/`:

- `ci.yml` — Primary pipeline: lint + typecheck + test (Python 3.11/3.12/3.13) + integration tests
- `test.yml` — Unit & integration tests with Codecov upload
- `lint.yml` — Ruff + MyPy checks
- `release.yml` — Build + publish to PyPI on version tags (`v*.*.*`)
- `action-test.yml` — Self-testing for the GitHub Action (`action.yml`)

## Environment variables

LLM configuration (for adaptive campaigns, pentesting agent, LLM judge):

- `ZIRAN_LLM_PROVIDER` — LLM provider name (default: `litellm`)
- `ZIRAN_LLM_MODEL` — Model name (default: `gpt-4o`)
- `ZIRAN_LLM_API_KEY_ENV` — Name of the env var holding the API key (e.g., `OPENAI_API_KEY`)
- `ZIRAN_LLM_BASE_URL` — Override base URL for the LLM provider
- `ZIRAN_LLM_TEMPERATURE` — Sampling temperature (default: `0.0`)
- `ZIRAN_LLM_MAX_TOKENS` — Max response tokens (default: `4096`)

API keys (set whichever your chosen provider requires):

- `OPENAI_API_KEY` — For OpenAI models
- `ANTHROPIC_API_KEY` — For Anthropic models

See `.env.example` for reference.
