Verdict: PASS
Gate: arch
Item: UI-523-DOCS
PR: taoq-ai/ziran#528
Head: 1d110eaa6cb2daf784c8d20a74980fff6b95649c
Confidence: high
Breaking: no (this diff is docs, licence text and spec moves; the breaking removal of the ui extra and `ziran ui` landed in #525 and #526 with BREAKING CHANGE footers, so the next release is a pre-1.0 minor, 0.44.0)

## Findings
- [low] COMMERCIAL-LICENSE.md:15 blocks: no. Owner review: v0.43.0 is a Covered Version (released under FSL, tag LICENSE is FSL) and ships the UI inside the Python package (`ziran/interfaces/web`, `ziran ui`). With "the web UI" gone from the definition, a 1.1 licensee gets no explicit commercial grant for that UI code; it keeps the FSL rights (non-competing use) and Apache-2.0 after the two-year conversion. A licensee can still argue the UI is part of "the Python CLI and library" as published on PyPI for v0.43.x. No 1.0 order form is signed, so nobody loses rights today. If the intent is to exclude the v0.43.x UI from commercial grants, saying so outright (for example "excluding the web UI shipped in v0.43.x") removes the ambiguity. If the intent is to include it, the current text is enough.
- [low] ziran/application/factories.py:5 blocks: no. Stale docstring "used by both the CLI and web UI"; outside this item's file list. Follow-up item.
- [low] ziran/interfaces/cli/html_report.py:23 blocks: no. Stale comment saying the CDN pin is "kept in step with the web UI's vis-network dependency", but that dependency no longer exists, so the pin has no anchor left. Follow-up: reword to state the pin on its own.
- [low] tests/unit/test_html_report.py:405 blocks: no. Same stale comment in the test; follow-up with html_report.py:23.
- [low] blocks: no. PR body: `Closes #520` closes the umbrella when this merges into develop (the default branch), before #520's last acceptance item (the release note in the GitHub release and CHANGELOG) can be met. Consider `Part of #520` and closing it after the release.
- [low] CLAUDE.md:25 blocks: no. The 024 and 025 Active Technologies lines still name a TypeScript/Node frontend and npm audit. They are not web UI entries, so they are in scope only if the owner wants CLAUDE.md free of frontend mentions.
- [low] blocks: no. `.dockerignore` and `.github/dependabot.yml` are outside the plan's Files list. Both are harmless leftovers from the #525/#526 gates (node_modules line; "npm" in a historical comment), and spec 085 records them.

## Probes
- Acceptance grep `grep -rn -i 'web ui\|ziran ui\|ziran\[ui\]' README.md docs mkdocs.yml` in a git archive copy at head: 5 lines, README.md:144 (moved notice) and roadmap 106/108/110/218. Matches acceptance 1.
- Spec conventions (constitution lines 84-88, CLAUDE.md): 008, 009 and 052 are under specs/archive/ with Status Superseded and the note; none is left under specs/. All file moves are 100% similarity renames, and the only content changes are the status and note lines, so nothing is deleted (never-delete holds). 010 and 026 stay Accepted with the note, which is the recorded assumption because 026 also covers the HTML report graph.
- mkdocs nav: every nav .md entry exists under docs/ (python check, 0 missing). No docs page links to specs 008/009/010/026/052 or to docs/assets/ui-*.png; the only ui-*.png mentions are in spec 085.
- Docs build: `uvx --with mkdocs-material mkdocs build` at base fb1aa57 and at head gives 8 WARNING lines each. All are links that were already broken in untouched files (gap-analysis.md, ../../../specs/* and others), so this change breaks no link. docs.yml runs without --strict.
- Roadmap anchor `#ziran-cloud` resolves to `## ZIRAN Cloud` (roadmap.md:211).
- Licence statement vs #520: NOTICE:9-15 puts v0.42.0 and earlier plus study-v1/v2 under Apache-2.0. The v0.43.0 tag LICENSE is FSL-1.1-ALv2 and that tag still holds ui/ and ziran/interfaces/web, and develop now has no ui/ or interfaces/web. The README line, the roadmap note, the CLI stub (main.py:2830) and the spec notes all name v0.42.0 as the last Apache-2.0 release with the UI. Clause 5 of the terms is unchanged and agrees. Consistent.
- Version claim: release-please-config.json has bump-minor-pre-major true and the manifest is 0.43.0. Commits b993da9 and 28f42d8 since v0.43.0 carry `!` and BREAKING CHANGE footers, so the next release is 0.44.0. This item's commit is `docs:` (hidden section); the repo merges with merge commits, so release-please reads the individual commits. The roadmap's v0.44.0 is correct, and the PR records it as an assumption with its overturn condition.
- README Docker section: the Dockerfile at head has `ARG ZIRAN_VERSION` and `ENTRYPOINT ["ziran"]`, and docker-compose.yml is gone on develop, so the new `docker build --build-arg ZIRAN_VERSION=... ; docker run ... ziran scan` usage matches the image.
- Order form now names version 1.1 of 2026-11-18, the same as the terms header. CONTRIBUTING CLA version 1.0 is a separate document and correctly unchanged.
- Confidence high: docs and licence text only, every claim checked at the head copy, and the build matched base. Only the licence-scope reading is a legal judgement, so it is left to the owner.

## Residual risk
The licence-scope reading of the v0.43.x UI under 1.1 is a legal judgement for the owner, not a mechanical defect. The stale code comments need a small follow-up.
