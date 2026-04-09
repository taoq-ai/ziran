# CLI Contract: `ziran analyze-traces`

## Synopsis

```
ziran analyze-traces --source <source> [--input <path>] [--project-id <id>] [--since <duration>] [--out <dir>] [--format <format>] [--verbose]
```

## Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `--source` | `Choice` | Yes | — | One of: `otel`, `langfuse` |
| `--input` | `Path` | Conditional | — | Trace file path. Required for `otel`; optional for `langfuse` (file export mode). |
| `--project-id` | `str` | Conditional | — | Langfuse project ID. Required for `langfuse` API mode (when `--input` is omitted). |
| `--since` | `str` | No | `24h` | Time window for Langfuse API pull (e.g., `24h`, `7d`, `1h`). Ignored for file input. |
| `--out` | `Path` | No | `./reports/` | Output directory for report files |
| `--format` | `Choice` | No | `json` | Report format: `json`, `markdown`, `html` |
| `--verbose` | `Flag` | No | `False` | Show per-session analysis details |

## Behavior

1. Ingest traces via the selected source adapter.
2. Reconstruct tool-call sequences per session/agent.
3. For each session, build a temporary knowledge graph and run `ToolChainAnalyzer.analyze()`.
4. Annotate findings with `observed_in_production=True`, timestamps, occurrence count.
5. Aggregate findings across sessions (deduplicate by chain signature, sum occurrences).
6. Generate report in the requested format to `--out/`.
7. Print summary: `Analyzed N sessions. Found M dangerous chains (K unique patterns).`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (file not found, parse error, Langfuse SDK missing, API auth failure) |

## Langfuse API Mode

When `--source langfuse` is used without `--input`, the command pulls traces from the Langfuse backend. Requires environment variables:
- `LANGFUSE_PUBLIC_KEY`
- `LANGFUSE_SECRET_KEY`
- `LANGFUSE_HOST`

If the `langfuse` package is not installed, the command exits with a clear error: `"Langfuse SDK not installed. Run: pip install ziran[langfuse]"`.
