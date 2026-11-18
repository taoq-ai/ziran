# Implementation Plan: ziran Claude Code plugin with four skills and a CLI drift test

**Branch**: `feat/059-claude-code-skills-plugin` | **Date**: 2026-10-18 | **Spec**: [spec.md](spec.md)
**Plan item**: WUWEI G1-SKILLS | **Base**: `develop` @ 5c3f90c

## Summary
Add a Claude Code plugin at `plugins/ziran/` with four skills, a root marketplace manifest, a
shared chain-type to ATLAS table, a README install section, and one pytest module that keeps the
skills honest against the live CLI, `action.yml` and `chain_patterns.yaml`. Markdown and JSON plus
one test file; no runtime code.

## Technical Context
**Language/Version**: Markdown, JSON; Python 3.11+ test (CI matrix 3.11, 3.12, 3.13).
**Primary Dependencies**: none new. The test uses pytest, Click's `CliRunner`, PyYAML (already
runtime deps) and `ziran.domain.entities.attack.AtlasTechnique`.
**Storage**: N/A.
**Testing**: pytest `@pytest.mark.unit`, runs in the CI unit job (`-m "not integration"`).
**Target Platform**: Claude Code plugin marketplace (GitHub source); CI.
**Constraints**: the test needs no `claude` CLI, network or LLM key.

## Layout

```text
.claude-plugin/marketplace.json
plugins/ziran/
├── .claude-plugin/plugin.json
├── README.md
└── skills/
    ├── audit-agents/SKILL.md
    ├── triage-findings/SKILL.md
    ├── set-up-scan/SKILL.md
    └── threat-model-agent/
        ├── SKILL.md
        └── references/atlas-chains.md
tests/unit/test_claude_plugin_skills.py
README.md   (one "Claude Code plugin" subsection under Install)
```

## Design decisions

### Parse only code, not prose
Commands are taken from fenced code blocks and inline code spans. A match is `ziran` not preceded
by a word character, `/`, `.`, `@` or `-`, followed by whitespace and a word; the rest of that
code line (cut at `|`, `;`, `&&`, `#`) holds the arguments. A `click.Group` (such as `cache`)
consumes the next word as its subcommand. The arguments go through the command's own Click
parser (`Command.make_parser(...).parse_args`), which reports unknown options and leftover
positional arguments; `click.Choice` values are then checked unless they are `<placeholders>`.
A `--flag` that appears in code outside any invocation must be an option of a command the same
file invokes.

### Errors name file and token
The checker returns strings `"<skill>/SKILL.md: ziran <cmd> <flag>: <reason>"`; the test asserts
the list is empty, so pytest prints every stale reference. A second test feeds the checker a
synthetic line with a removed flag and a removed command to prove it reports both.

### Suppressions template drives a real gate run
The triage skill's `yaml` block with `entries:` is the template. The test runs `ziran ci` once with
an empty file to read the printed `fingerprint=`/`content_hash=`, loads the template, sets those
two values and a future `expires`, keeps the template's other keys, and runs `ziran ci` again. The
run must not exit 2 and must print `suppressed 1`. `SuppressionFile` forbids unknown keys, so a
wrong key in the template fails the test.

### ATLAS table rows group chain types
Each row's first cell lists chain types in backticks; the second lists `AML.T` IDs. The test
collects all types from rows and compares both ways with the types in `chain_patterns.yaml` plus
the `vulnerability_type="..."` literals in `chain_analyzer.py`; every `AML.T` ID
anywhere under `plugins/ziran/` must be an `AtlasTechnique` value.

### Environment isolation in the test
`GITHUB_OUTPUT` and `GITHUB_STEP_SUMMARY` are removed with `monkeypatch` and `ziran ci` gets
`--no-github-annotations --no-github-summary`, so the test never writes to the CI job's own
summary. LLM key variables are removed for the dry run.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | No code under `ziran/`. |
| II. Type safety | PASS | Test functions annotated; no runtime code. |
| III. Tests | PASS | One `@pytest.mark.unit` module; red run before the plugin files exist. |
| IV. Async-first | N/A | No I/O code in `ziran/`. |
| V. Extensibility | PASS | No vectors or adapters touched. |
| VI. Simplicity | PASS | No new dependency, no helper module, one test file. |

No violations.

## Rollback
Revert the merge commit. Nothing under `ziran/` changes, so the package is unaffected; users who
installed the plugin keep their cached copy until they run `claude plugin uninstall ziran@ziran`.
