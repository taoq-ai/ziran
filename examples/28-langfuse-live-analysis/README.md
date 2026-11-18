# Langfuse Live Analysis

Pull your agent's tool calls live from Langfuse and flag dangerous tool chains, with no trace
export. `ziran analyze-traces --source langfuse` without `--input` reads the Langfuse public API
(`GET /api/public/v2/observations`) over HTTPS. No LLM is called.

## Prerequisites

- `pip install "ziran>0.42.0"` (the first release with the live pull; no extra needed)
- A Langfuse project that records tool steps as `TOOL` or `SPAN` observations
- The project's API keys, from its settings page:

```bash
export LANGFUSE_PUBLIC_KEY=pk-lf-...
export LANGFUSE_SECRET_KEY=sk-lf-...
export LANGFUSE_HOST=https://cloud.langfuse.com   # or https://us.cloud.langfuse.com, or your own host
```

## Run

```bash
./run.sh                       # the last 24 hours
./run.sh --since 7d            # the last week
./run.sh --session-id s-123    # one session
./run.sh --incremental         # only what arrived since the last --incremental run
```

`run.sh` checks the two keys and runs:

```bash
ziran analyze-traces --source langfuse --out reports "$@"
```

The report lands in the git-ignored `reports/trace_analysis.json`. The command exits `1` when a
critical chain matched (for example `read_file` then `http_request` in one trace), `0` when none
did, and `2` when it could not finish (missing keys, a bad `--since`, an HTTP error, or rate
limiting that outlasted three retries).

## Run it on a schedule

`--incremental` keeps its cursor in `.ziran/trace_cache/` of the working directory, so run it from
the same directory each time. An hourly cron entry that also files GitHub issues for matches:

```cron
0 * * * * cd /srv/ziran && ziran analyze-traces --source langfuse --incremental --out reports --alert --config alerts.yaml
```

See the [analyze-traces guide](https://taoq-ai.github.io/ziran/guides/analyze-traces/) for the
`alerts.yaml` format and the live-API details.
