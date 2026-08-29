# Runtime Configuration

Settings that tune how ZIRAN talks to LLM providers at runtime.

## LLM rate-limiting and retry

When AI-powered features are enabled (`--llm-provider` / `--llm-model`), every
outbound LLM provider call routes through a shared rate-limiting and retry
layer. This keeps high-concurrency campaigns from tripping provider limits and
prevents transient throttling from being mistaken for attack failures.

Two things happen on every call:

1. **Client-side pacing.** A token bucket admits at most `--llm-rpm` requests
   per minute and `--llm-tpm` tokens per minute. When the bucket is empty the
   call waits rather than firing and getting rejected.
2. **Retry with backoff.** Retryable provider errors (HTTP 429 and transient
   5xx: 500, 502, 503, 504) are retried up to `--llm-max-retries` times with
   exponential backoff plus full jitter. A provider `Retry-After` header is
   honored when it is larger than the computed delay. Non-retryable errors
   (400, 401, 403, 404, ...) fail immediately.

### Flags and environment variables

| Flag | Env var | Default | Meaning |
|------|---------|---------|---------|
| `--llm-rpm` | `ZIRAN_LLM_RPM` | per provider (see below) | Requests per minute. `0` disables request pacing. |
| `--llm-tpm` | `ZIRAN_LLM_TPM` | `0` (disabled) | Tokens per minute. `0` disables token pacing. |
| `--llm-max-retries` | `ZIRAN_LLM_MAX_RETRIES` | `3` | Retries for throttled/transient errors. `0` disables retry. |

These flags are available on both `ziran scan` and `ziran pentest`.

Token-per-minute accounting uses a character-based estimate (`chars / 4`) for
the prompt; it paces the bucket but is not billed exactly.

### Per-provider defaults

When `--llm-rpm` is not set, the request-per-minute default is chosen from the
provider name:

| Provider | Default RPM |
|----------|-------------|
| `openai` | 10000 |
| `azure` | 10000 |
| `anthropic` | 4000 |
| `bedrock` | 4000 |
| anything else (incl. `litellm`) | 60 |

Raise these with `--llm-rpm` for your account's actual limits, or set
`--llm-rpm 0` to opt out of client-side pacing entirely.

### Logs: throttled vs failed

Throttle events are logged at `WARNING` and record the provider, status code,
attempt number, and backoff delay, for example:

```
WARNING  provider throttled (provider=anthropic, status=429), retrying 1/3 after 0.42s
```

Only a call whose retries are exhausted raises an error, and that error names
the retry count (`... failed after 3 retries (provider throttled, status=429)`),
so a genuinely throttled call is never silently recorded as an agent refusal or
attack failure.

### Example

```bash
# Pace to 120 requests/min, retry throttled calls up to 5 times
ziran scan --target ./target.yaml \
    --llm-provider anthropic --llm-model claude-sonnet-4-20250514 \
    --concurrency 20 --llm-rpm 120 --llm-max-retries 5
```
