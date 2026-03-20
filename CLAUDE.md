# ziran Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-03-20

## Active Technologies
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + asyncio, dataclasses, logging, OpenTelemetry (tracing) (003-split-agent-scanner)
- N/A (in-memory knowledge graph via NetworkX) (003-split-agent-scanner)
- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + Pydantic (config models), re (stdlib regex) (003-precompile-regex-patterns)

- Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + click (CLI only), PyYAML, Playwright (optional), boto3 (optional), LangChain (optional), CrewAI (optional) (002-extract-shared-factories)

## Project Structure

```text
src/
tests/
```

## Commands

cd src [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] pytest [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] ruff check .

## Code Style

Python 3.11+ (CI matrix: 3.11, 3.12, 3.13): Follow standard conventions

## Recent Changes
- 003-precompile-regex-patterns: Added Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + Pydantic (config models), re (stdlib regex)
- 003-split-agent-scanner: Added Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + asyncio, dataclasses, logging, OpenTelemetry (tracing)

- 002-extract-shared-factories: Added Python 3.11+ (CI matrix: 3.11, 3.12, 3.13) + click (CLI only), PyYAML, Playwright (optional), boto3 (optional), LangChain (optional), CrewAI (optional)

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
