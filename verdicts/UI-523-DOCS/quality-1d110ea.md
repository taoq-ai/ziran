Verdict: PASS
Gate: quality
Item: UI-523-DOCS
PR: taoq-ai/ziran#528
Head: 1d110eaa6cb2daf784c8d20a74980fff6b95649c
Confidence: medium

## Findings
- [low] docs/community/roadmap.md:108 blocks: no. The v0.44.0 number is an assumption (manifest is 0.43.0, release-please bump-minor-pre-major); the PR spec records it. If the release is cut under another number, lines 108 and 218 change.
- [low] COMMERCIAL-ORDER-FORM.md:42 blocks: no. The template placeholder "[X] of [DATE]" is now hard-coded to 1.1 / 2026-11-18, so the next terms version needs this line edited again. It is what #523 asked for ("point to the new terms version").
- [low] blocks: no. CI at the time of reading: lint, typecheck, dependency-audit, detection-accuracy-gate, pentest-eval-gate and CodeQL-actions passed; test 3.11/3.12/3.13, integration-test and the CodeQL python/js analyses were still pending. The merge needs them green.

## Probes
- Acceptance 1: `grep -rn -i "web ui\|ziran ui\|ziran\[ui\]" README.md docs mkdocs.yml` at the head returns 4 lines: README.md:144 (moved notice), docs/community/roadmap.md:106, 108, 110 (v0.13 section, moved note) and 218 (ZIRAN Cloud entry). Exactly the moved notice and roadmap lines. docs/concepts/browser-scanning.md reworded to "chat web interfaces" (target agents, not the product UI); harmless.
- Acceptance 2: `uvx --with mkdocs-material mkdocs build --strict` in git-archive copies of the head and of origin/develop (fb1aa57): both abort with 7 warnings, and the WARNING/ERROR lines are identical (diff empty). The warnings are in guides/policy-refresh-automation.md and reference/benchmarks/*; none is in a touched file. The roadmap `#ziran-cloud` anchor resolves (no anchor message; the heading exists at roadmap.md:211). No broken link is new. "No broken links" is met relative to develop; the 7 existing ones stay.
- Acceptance 3: COMMERCIAL-LICENSE.md line 3 is "version 1.1, 2026-11-18"; the definition of ziran lists CLI and library, GitHub Action and Claude Code plugin; grep for "web ui|UI" in both COMMERCIAL files returns nothing. No other file cites licence terms 1.0 (the CLA 1.0 in CONTRIBUTING.md is a separate document). The PR body shows the whole licence diff for owner review, with a Rollback line and an Announcement link.
- Specs: 008, 009 and 052 are renamed (pure renames apart from spec.md) into specs/archive/, Status Superseded plus the one-line Note. 010 and 026 (already in archive) gain the Note only. Nothing outside specs/archive and specs/085 links to the old paths; the remaining mentions of `specs/008-...` are branch names inside the archived specs.
- Docker (podman 5.8.2, docker is aliased to podman): `podman build --build-arg ZIRAN_VERSION=0.0.0 -t ziran-sq523 .` succeeded at the head; `podman run --rm -v "$PWD:/work" -w /work ziran-sq523 scan --help` printed the scan usage (rc 0); `--version` printed "ziran, version 0.0.0". The README `docker run ... scan --target target.yaml` form matches the option set. Image removed afterwards.
- Assets: `grep -rnE "ui-(dashboard|findings|library|new-run|settings)"` outside archived specs and spec 085 finds no reference to the 5 deleted PNGs; the docs build shows no missing-image warning.
- CLAUDE.md: the diff removes only the Active Technologies lines tagged 008, 009, 010, 026 and 052; the file still has the header, Project Structure, speckit workflow, gates and branching sections intact. The `feat(ui)` commit-message example at line 145 is generic and fine. Removing the 026 lines also drops its "Report - vis-network via CDN" note, which still holds for the HTML report; this is minor.
- Leftovers: .dockerignore drops `node_modules/`; the .github/dependabot.yml change is a comment only.
- README streaming extra: `ziran[streaming]` was already in README and pyproject.toml (line 86); the PR correctly does not add it twice.
- Tests/mutants: docs-only change (plus the licence text); no test needed and no mutants run (nothing guards behaviour).
- Simplicity: none. The spec 085 triple (spec, plan, tasks) is process material the repository's speckit rule requires; nothing in the diff is code that could be deleted.

## Residual risk
The PR's 3 test jobs and integration-test had not finished when I read the checks once; docs-only, so failure is unlikely but the merge must wait for green. The v0.44.0 wording is an unconfirmed release number.
