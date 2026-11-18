Verdict: PASS
Gate: arch
Item: G6-RELEASE
PR: taoq-ai/ziran#532
Head: f6635be7c7bad349941543790b15dfc3681dfea4
Confidence: high
Breaking: yes: the release ships the removal of the ui extra, the ziran ui command, ziran.interfaces.web and the web UI in the Docker image for clients of v0.43.0 (gated at 0388a66, owner-confirmed, announced in #520). Under bump-minor-pre-major that is a minor, 0.43.0 to 0.44.0. This PR's own diff changes no API.

## Findings
- [low] CHANGELOG.md:13 blocks: no. Three fixes appear twice (detectors 6f7ccd7/fea1eaa, mcp c7da589/03e3b6c) because the same change landed by two commits on the release path. Cosmetic only.

## Probes
- `gh pr view 532`: head f6635be, base main; files are .release-please-manifest.json, CHANGELOG.md and plugins/ziran/.claude-plugin/plugin.json only.
- `git show f6635be` parent is 68a9588; `git diff 0388a66 68a9588 --stat` printed nothing, so the released tree equals the four-gated 0388a66 tree (68a9588 is the merge of 0388a66 into main).
- SemVer step: release-please-config.json has bump-minor-pre-major true; `git log v0.43.0..68a9588 --no-merges` shows two `!` commits (b993da9, 28f42d8). Pre-1.0 breaking changes give a minor, so 0.43.0 -> 0.44.0 is correct.
- Version agreement: in a `git archive f6635be` copy, `python3 -I` parsed the manifest "." = 0.44.0 and plugin.json version = 0.44.0. plugin.json is release-please's configured extra-file ($.version). The package version comes from the git tag (hatch-vcs), so tag v0.44.0 sets it. A grep for 0.43.0 outside CHANGELOG and lock files found no stale references.
- PR body carries `Announcement: https://github.com/taoq-ai/ziran/issues/520`, and the arch verdict at 0388a66 records the owner's confirmation.
- Confidence high: the diff is three metadata files, the tree equality is exact and the bump rule is mechanical.

## Residual risk
Publishing depends on the tag v0.44.0 being cut from the merge commit. The release workflow does that after merge, and this gate did not see it.
