# Incremental scanning

`ziran scan --incremental` reuses the stored result of every attack vector whose inputs have not
changed since the last run, and executes only the rest. It is meant for fast local iteration: you
edit one vector or one tool, re-run, and only the affected vectors hit the agent again.

The cache is **opt-in only**. ZIRAN never turns it on by itself, in CI or anywhere else.

!!! warning "A stale cache hides findings"
    The cache can only see the files ZIRAN hashes. A remote target can change its model, its
    server-side system prompt, its data or the tools behind its API without any change to your
    target YAML. A cached "not vulnerable" result then hides a real finding. Do not use
    `--incremental` for release gates, scheduled scans or anything you sign off on.

## When to use it

- Local iteration on an in-process agent (`--framework` + `--agent-path`) or on your own attack
  vectors (`--custom-attacks`).
- Pre-commit hooks and pull-request jobs where speed matters more than catching changes on the
  target side.

## When not to use it

- Release gates, scheduled CI scans, and the job that guards `main`.
- After you changed the target's model, its server-side prompt, or anything else ZIRAN cannot
  hash (see [What invalidates a cached result](#what-invalidates-a-cached-result)). Run
  `ziran cache clear` or pass `--no-cache` instead.

## Usage

```bash
# First run executes everything and fills .ziran/scan_cache/
ziran scan --framework langchain --agent-path agent.py --incremental

# Second run reuses every unchanged vector
ziran scan --framework langchain --agent-path agent.py --incremental

# One fresh run without touching the cache (neither read nor written)
ziran scan --framework langchain --agent-path agent.py --incremental --no-cache

# Delete every cached result
ziran cache clear
```

`--no-cache` wins over `--incremental`; on its own it does nothing. The scan summary shows an
`Incremental Cache` row such as `4 cached · 1 executed`, and the JSON report carries the same
counts in `metadata.scan_cache`:

```json
"scan_cache": {"executed": 1, "cached": 4}
```

A reused result keeps its verdict and evidence, gains `evidence.cached: true`, and reports zero
token usage (nothing was sent to the agent). Findings, the knowledge graph, `--stop-on-critical`,
token budgets and the CI gate treat it exactly like a fresh result: a cached vulnerability is
still counted in `total_vulnerabilities`.

The cache lives in `.ziran/scan_cache/` relative to the working directory, one file per vector:
`.ziran/scan_cache/<campaign key>/<vector id>.json`.

## What invalidates a cached result

A result is reused only when all of these are unchanged:

- the attack vector itself (every field of the vector, including prompts, indicators, severity and
  tags);
- the bytes of the `--target` YAML or the `--agent-path` file, plus `--protocol` and
  `--framework`;
- the discovered capabilities (id, name, type, description, parameters, dangerous), in any order;
- the detector settings: disabled detectors, match types, refusal languages, every threshold in
  `.ziran/detectors.yaml` (ensemble, prefilter and semantic included), the judge model and the
  ensemble and prefilter models;
- `--encoding`, `--streaming`, `--quality-scoring` and the many-shot settings;
- the installed ZIRAN version (an upgrade invalidates everything).

## What is never cached

- Results that carry an error, and failed attacks without any agent response (a connection
  failure looks like that; caching it would hide a finding).
- Attacks that timed out.
- Vectors whose id is not a safe file name (letters, digits, `_`, `.`, `-`, at most 128
  characters).
- Scans with `--encoding word_shuffle` (the shuffle is random) and scans with
  `--strategy llm-adaptive` (not deterministic). `--incremental` prints a warning and runs
  without the cache, as it does when `--agent-path` is not a single file.

## Pre-commit recipe

Run a quick incremental scan when agent code or custom vectors change:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ziran-incremental
        name: ziran incremental scan
        entry: ziran scan --framework langchain --agent-path agent.py --custom-attacks attacks/ --coverage essential --incremental
        language: system
        pass_filenames: false
        files: ^(agent\.py|attacks/.*\.ya?ml)$
```

## CI recipe

A pull-request job may opt in and restore the cache per branch. The job that guards `main` and
every release always runs without it. Neither job enables the cache implicitly: the flag is
written out where it is used.

```yaml
jobs:
  pr-scan:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: .ziran/scan_cache
          key: ziran-scan-${{ github.head_ref }}-${{ github.sha }}
          restore-keys: ziran-scan-${{ github.head_ref }}-
      - run: pip install ziran
      - run: ziran scan --target target.yaml --incremental

  release-scan:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install ziran
      - run: ziran scan --target target.yaml   # no --incremental: always a full scan
```

## Do not commit the cache

`.ziran/scan_cache/` holds prompts and agent responses, exactly like the result JSON in
`--output`. Treat it like scan results: never commit it. It is git-ignored in the ZIRAN
repository; add it to your own `.gitignore`:

```gitignore
.ziran/scan_cache/
```

(`.ziran/detectors.yaml` and `.ziran/prices.yaml` are configuration and are meant to be
committed, so do not ignore the whole `.ziran/` directory.)

## Limitations

- **Remote targets can change unseen.** Only the target YAML bytes are hashed, not the service
  behind it and not environment variables referenced with `!env`.
- **Imports are not hashed.** For in-process agents only the `--agent-path` file is hashed, not
  the modules it imports.
- **Editable installs.** The ZIRAN version is the installed package version; editing ZIRAN's own
  source in a development checkout does not invalidate the cache. Run `ziran cache clear`.
- **Degraded judge verdicts.** When an LLM judge call times out, the detector pipeline falls back
  silently, and that verdict can be cached. Use `--no-cache` or `ziran cache clear` if a judge
  outage hit a run.
- **Counts.** `executed` counts vectors run in this invocation, `cached` counts reused results.
  Vectors skipped by a token budget, or restored from a checkpoint with `--resume`, are in
  neither.
- **No pruning.** Every distinct configuration gets its own directory and nothing expires.
  `ziran cache clear` deletes everything.
- **API users.** `AgentScanner` uses a cache only when `scanner_config["scan_cache"]` holds a
  `ScanCache`. The `llm-adaptive` refusal lives in the CLI, so do not combine a `ScanCache` with
  `LLMAdaptiveStrategy` yourself.
