# Implementation Plan: document the web UI move

**Branch**: `docs/523-ui-move` | **Date**: 2026-11-18 | **Spec**: [spec.md](spec.md)

## Approach

Text edits only. No code, no new dependency, no test: docs and licence text only.

- README: drop the `ui` extra line, add the moved line under Install, replace `### Web UI` with
  `### Docker` showing `docker build --build-arg ZIRAN_VERSION=<version> -t ziran .` and
  `docker run ... ziran scan --target target.yaml`.
- docs: `concepts/knowledge-graph.md`, `guides/interpreting-results.md`,
  `guides/cicd-integration.md`, `guides/long-running-campaigns.md`, `community/roadmap.md`,
  and `concepts/browser-scanning.md` for the grep.
- Delete `docs/assets/ui-*.png` (no reference left).
- COMMERCIAL-LICENSE.md: version line and the definition of ziran. COMMERCIAL-ORDER-FORM.md:
  the Annex 1 version line.
- `git mv` specs 008, 009, 052 to `specs/archive/`, status Superseded plus a note; the note on
  010 and 026.
- CLAUDE.md: delete the Active Technologies lines tagged 008, 009, 010, 026 and 052.
- `.dockerignore` and `.github/dependabot.yml` leftovers.

## Checks

- The acceptance grep.
- `uvx --with mkdocs-material mkdocs build --strict`, compared with the same build of the base
  (mkdocs is not in the dev group; the docs workflow uses `uvx`).
