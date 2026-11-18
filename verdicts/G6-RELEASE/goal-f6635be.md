Verdict: PASS
Gate: goal
Item: G6-RELEASE
PR: taoq-ai/ziran#532
Head: f6635be7c7bad349941543790b15dfc3681dfea4
Confidence: medium

## Findings
- [low] blocks: no. GitHub release note (added after merge) must carry the #520 draft note, see Probes.

## Probes
- Head confirmed with gh pr view 532: f6635be7c7bad349941543790b15dfc3681dfea4, OPEN. CHANGELOG.md read at that sha via git show.
- Stand-in runtime: the GitHub release body does not exist yet; release-please fills it from the PR body, which carries the same BREAKING CHANGES text as CHANGELOG. The #520 draft note ("The web UI has moved...") is not in it verbatim. Probe that settles it: gh release view v0.44.0 after merge.
- Sibling path: the plugin.json version bump and manifest 0.44.0 agree; the streaming extra exists in pyproject.toml at the head (line 86, also in the all list).
- Repeated defect: the 0.43.0 section is untouched by the diff.
- CHANGELOG 0.44.0 has BREAKING CHANGES for ui and web. Both state: UI continues in ZIRAN Cloud and ZIRAN Enterprise (info@taoq.ai); v0.42.0 and earlier still include it under Apache-2.0. The web entry adds ziran[streaming] for WebSocket targets and the removal of the ui extra and ziran ui. This matches #520's message.
- Drift: the ui entry adds the Docker image and docker-compose.yml removal, which is a true consequence and not out of scope. #520's sentence that the knowledge graph in the HTML report is unchanged is absent from the CHANGELOG.
- The GitHub release should carry: the two BREAKING CHANGES entries; the #520 draft note, including "Everything else in ziran is unchanged, including the interactive knowledge graph in the HTML report"; the v0.42.0 Apache-2.0 and v0.43.x FSL-1.1-ALv2 licence statement; pip install ziran[streaming] for WebSocket targets; Docker image is a CLI only.
- Not checked here: the other G-6 acceptance items (no ui/, no web dir, no Node.js in CI, quality gates), which belong to #521-#523 and earlier gates.

## Residual risk
The GitHub release note after merge is unverified. If it is published unedited from release-please, it meets the BREAKING CHANGES requirement but lacks the "everything else unchanged" sentence.
