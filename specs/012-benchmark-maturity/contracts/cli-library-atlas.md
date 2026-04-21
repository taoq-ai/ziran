# Contract: CLI `--atlas` Filter

**Applies to**: `ziran library` subcommand in `ziran/interfaces/cli/main.py`.

## Behaviour

```text
$ ziran library --atlas AML.T0051
```

Lists all attack vectors whose `atlas_mapping` contains the supplied technique ID.

## Flag

| Attribute | Value |
|---|---|
| Flag | `--atlas` |
| Short | (none) |
| Accepts | Single ATLAS technique ID string matching an `AtlasTechnique` enum value |
| Case | Sensitive (canonical ATLAS casing) |
| Invalid input | Click error with "did-you-mean" hint via `difflib.get_close_matches` |
| Combinable | Yes — can be combined with `--owasp`, `--category`, `--tag`, `--severity`; filters compose as AND |

## Output

The existing library table gains an ATLAS column (analogous to the existing OWASP column):

```text
  ID                  Name                        Severity  Category        OWASP    ATLAS
  ──────────────────────────────────────────────────────────────────────────────────────────────
  pi_basic_override   Basic system prompt override  high    prompt_inj…     LLM01    AML.T0051
```

When filtered by `--atlas`, only vectors matching the supplied technique are shown. The column stays visible in unfiltered listings too.

## Contract tests

Tests in `tests/integration/test_cli_atlas_filter.py`:

1. Valid technique ID → non-empty list of vectors, all containing that technique.
2. Valid technique ID with no matches → empty list + informational message.
3. Invalid technique ID → Click exit code 2, error message listing close matches.
4. Combined `--atlas X --owasp LLM01` → AND semantics (vectors matching both).
5. Invalid combination (`--atlas X --category Y` where no vector satisfies both) → empty result, no error.
