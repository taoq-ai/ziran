# Feature Specification: document the web UI move

**Feature Branch**: `docs/523-ui-move`
**Created**: 2026-11-18
**Status**: Active
**Plan item**: UI-523-DOCS (goal G-6), GitHub issue #523, the last part of #520.
**Base**: `develop` @ fb1aa57 (after #525 and #526 removed the web backend and the frontend).

## The promise in our own words

#525 and #526 took the web UI code out of ziran. This item makes the words match. The README
loses `pip install ziran[ui]` and the Web UI section, and says in one line that the UI is in
ZIRAN Cloud and ZIRAN Enterprise, with v0.42.0 as the last Apache-2.0 release that has it. The
Docker part of that section becomes plain CLI image usage. Four docs pages stop describing the
web UI as a second surface. The roadmap marks v0.13 as moved and lists the UI, the findings and
OWASP compliance view and the knowledge-graph explorer under ZIRAN Cloud.

The commercial terms drop "the web UI" from the definition of ziran and become version 1.1 of
2026-11-18; the order form names 1.1. No order form was signed under 1.0. Specs 008, 009 and 052
move to `specs/archive/` as Superseded, and they and 010 and 026 get a one-line note. CLAUDE.md
loses its web UI Active Technologies entries. Leftovers from the #525 and #526 gates go too: the
unused UI screenshots, the `node_modules/` line in `.dockerignore` and the npm mention in the
Dependabot header.

## Acceptance scenarios

1. Given the PR head, when `grep -rn -i "web ui\|ziran ui\|ziran\[ui\]" README.md docs mkdocs.yml`
   runs, then it returns only the README moved notice and the roadmap entries.
2. Given the docs workflow, when the site builds, then no link is broken by this change.
3. Given COMMERCIAL-LICENSE.md, when read, then it is version 1.1 and its definition of ziran
   names no web UI.

## Assumptions

- The release that removes the UI is v0.44.0: release-please has `bump-minor-pre-major` and the
  current version is 0.43.0. Overturned if the release is cut under another number; then the two
  roadmap lines change.
- The note on 010 and 026 says the UI moved out, not that the spec is superseded, because 026
  also covers the HTML report graph, which stays.
- `docs/concepts/browser-scanning.md` said "chat web UIs" about target agents. It now says "chat
  web interfaces" so the acceptance grep finds only the move notices.
