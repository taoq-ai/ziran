# Quickstart: release-please Automated Releases

## How Releases Work Now

1. Push commits to `main` following Conventional Commits format (`feat:`, `fix:`, etc.)
2. release-please automatically creates/updates a **Release PR** with the proposed version bump and changelog
3. Review and merge the Release PR when ready to release
4. release-please creates a git tag (e.g., `v0.14.0`)
5. The tag triggers the existing `release.yml` → lint → test → build → publish to PyPI → GitHub Release

## Making a Release

No manual steps needed beyond merging the Release PR:

1. Write code, commit with conventional messages
2. A Release PR appears (or updates) automatically
3. Merge the Release PR when ready
4. Done — PyPI publish happens automatically

## Version Bumps

| Commit Type | Version Bump | Example |
|---|---|---|
| `fix: ...` | Patch (0.13.0 → 0.13.1) | Bug fixes |
| `feat: ...` | Minor (0.13.0 → 0.14.0) | New features |
| `feat!: ...` or `BREAKING CHANGE:` | Major (0.13.0 → 1.0.0) | Breaking changes |
| `docs:`, `chore:`, `ci:`, etc. | No bump | Non-user-facing |

## Troubleshooting

- **Release PR not appearing?** Only `feat:` and `fix:` commits trigger version bumps. Commits like `docs:` or `chore:` alone won't create a Release PR.
- **Wrong version?** Check `.release-please-manifest.json` — it tracks the current version.
- **Publish didn't trigger?** The token used by release-please must be able to trigger downstream workflows. Check the `RELEASE_PLEASE_TOKEN` secret.
