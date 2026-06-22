# Contract: Dependabot Scheduled-Update Config

**File**: `.github/dependabot.yml` (NEW)
**Satisfies**: FR-011; clarification Q1 (committed in-repo config)

## Required shape

`version: 2` with three `updates` entries, each **weekly** and **grouped** (one PR per ecosystem per run to avoid per-package noise):

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      python-dependencies:
        patterns: ["*"]

  - package-ecosystem: "npm"
    directory: "/ui"
    schedule:
      interval: "weekly"
    groups:
      frontend-dependencies:
        patterns: ["*"]

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      actions:
        patterns: ["*"]
```

## Rules

- **Grouping is mandatory** — ungrouped output recreates the per-package PR spam this prevents (FR-011).
- `pip` directory is repo root (`/` — where `pyproject.toml`/`uv.lock` live); `npm` directory is `/ui`.
- `github-actions` included so pinned action SHAs/tags don't drift into staleness.
- Security updates remain enabled independently of this scheduled-version config; this config governs *routine* updates.
- Optional: `open-pull-requests-limit` and `commit-message.prefix: "chore"` to match the repo's Conventional-Commits + release-please convention.

## Verification

After commit, Dependabot validates the file (Insights → Dependency graph → Dependabot). A malformed file surfaces as a Dependabot error on the repo, which counts as a failure of this contract.
