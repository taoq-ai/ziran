Verdict: PASS
Gate: security
Item: G6-RELEASE
PR: taoq-ai/ziran#532
Head: f6635be7c7bad349941543790b15dfc3681dfea4
Confidence: high

## Findings
- [low] blocks: no. CHANGELOG.md lists three fixes twice (detectors demote, mcp no-chat placeholder) because both the develop commit and its main cherry-pick are counted; cosmetic only.

## Probes
- PR head from `git fetch origin pull/532/head`: f6635be, base main; 68a9588 (origin/main) is an ancestor.
- `git diff 68a9588 f6635be --stat`: 3 files, +27 -2 (.release-please-manifest.json, CHANGELOG.md, plugins/ziran/.claude-plugin/plugin.json). Manifest and plugin.json change only "0.43.0" to "0.44.0"; CHANGELOG adds markdown text and commit links on github.com/taoq-ai/ziran only. Nothing executable.
- `git diff 68a9588 f6635be | grep -iE 'token|secret|key|password|\$\(|backtick'`: 0 matches. No secrets.
- `git diff 0388a66 68a9588 --stat`: empty, exit 0. The released tree equals the tree that passed security-0388a66 (PASS, high).
- `git diff 0388a66 68a9588 -- .github/workflows/release.yml`: 0 lines, so release.yml at main is the gated version (tag trigger, top-level contents: read, id-token: write only on the PyPI publish jobs, verify-tag job).
- pyproject.toml uses hatch-vcs (dynamic version), so the tag v0.44.0 sets the package version; release.yml checks that the package version matches the tag.
- Confidence high: the diff is three data files and both tree-equality checks came back empty. The gaps already noted in security-0388a66 (pypi environment has no protection rules, RELEASE_TAG expanded inline) are still there and nothing here changes them.

## Residual risk
Publishing is still gated only by verify-tag and the PyPI trusted-publisher binding (an existing gap noted in security-0388a66).
