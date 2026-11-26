# Feature Specification: a compact engine README that points to the docs site

**Feature Branch**: `docs/108-readme-compact`
**Created**: 2026-11-26
**Status**: Active
**Plan item**: E-README-COMPACT (goal G-f)

## The promise in our own words

The README on develop is 329 lines and 1,816 words (`wc -lw README.md`). The owner finds it too
long. The new README fits on about two screens and stays under 120 lines. It holds: what ZIRAN is
in one paragraph, install, a three-command quick start, one example output, a short list of what
it finds, links to the docs site for frameworks, benchmarks, the CI gate, the Claude Code plugin,
the comparison table and contributing, and the license paragraph (source-available under
FSL-1.1-ALv2, not open source). It names no partner, demo, pricing or meeting.

Nothing is lost. Each README section that leaves is already on a docs page, or moves to one in
the same change:

| README section | Docs home |
|---|---|
| How it works (pipeline, five stages, side effects, trust, strategies) | `docs/index.md` "How It Works" (moved) |
| How it compares (table, "is not" paragraph) | `docs/index.md` "How It Compares" (replaced with the newer README table) |
| Citation | `docs/index.md` "Citation" (moved) |
| Benchmarks | `docs/reference/benchmarks/coverage-comparison.md` (already there) |
| Install extras `pentest`, `otel` | `docs/getting-started.md` (added) |
| Docker | `docs/getting-started.md` "Docker" (moved) |
| Claude Code plugin install | `docs/guides/claude-code.md` "Claude Code plugin for ZIRAN" (moved) |
| Quick start CLI, Python API | `docs/getting-started.md`, `docs/reference/cli.md` (already there) |
| Remote agents | `docs/guides/remote-agents.md` (already there) |
| Reports | `docs/getting-started.md` "Understanding Results" (report image added) |
| CI/CD | `docs/guides/ci-integrations.md` (already there) |
| Development, contributing | `docs/community/contributing.md` (already there) |

## Acceptance scenarios

1. Given the new README, when rendered on GitHub, then it is under 120 lines and every link
   resolves to an existing docs page or anchor.

## Assumptions

- The web UI sentence (ZIRAN Cloud and Enterprise) leaves the README and is not moved: it is a
  commercial offer, which the item keeps out of the public README. Overturned if the owner wants
  it on a docs page.
- The citation drops its `version = {0.25.0}` field, which was stale. Overturned if a citation
  must pin a version.
- The hero image is decoration and is not moved; the pipeline and report images are.
- The example output is the real `ziran audit agents/` output of
  `examples/24-claude-code-agent-audit/` at 120 columns, with the summary panel and the
  recommendations trimmed and marked `...`.
