# Feature Specification: ziran Claude Code plugin with four skills and a CLI drift test

**Feature Branch**: `feat/059-claude-code-skills-plugin`
**Created**: 2026-10-18
**Status**: Active
**Plan item**: WUWEI G1-SKILLS (goal G-1), tier `full`.
**Base**: `develop` @ 5c3f90c.
**Scope**: a Claude Code plugin under `plugins/ziran/`, a marketplace manifest at the repository
root, one pytest drift test, one README install section. No file under `ziran/` changes.

## Promise in my words

A Claude Code user runs `/plugin marketplace add taoq-ai/ziran` and `/plugin install ziran@ziran`
and gets four skills. Each skill tells Claude when to act and what to add beyond running a
command: reading the findings, explaining the chain, proposing the narrowest fix, writing a
justified suppression. The skills name real `ziran` commands and flags, so a test in the normal
pytest run checks every command and flag a skill names against the live Click tree, runs the
offline ones against committed examples and fixtures, checks the GitHub Action inputs the audit
skill uses, and checks that the chain-type to MITRE ATLAS table covers every chain type ZIRAN can
report with technique IDs that exist in `AtlasTechnique`. When the CLI changes under the skills,
CI goes red and names the skill file and the stale command or flag.

The four skills:

- `audit-agents`: audit a Claude Code plugin, `agents/` directory or agent `.md` file with
  `ziran audit` (`--sarif`, `--write-baseline`, `--baseline`), interpret `CC001`/`SA00x`/`BL00x`,
  propose the narrowest `tools:` fix, and give a GitHub Action snippet (`command: audit`, `path`,
  `baseline`).
- `triage-findings`: take a scan result JSON through `ziran report`, `ziran ci --suppressions
  --sarif`, `ziran export-policy` and `ziran poc`; decide fix or accept; write a suppressions
  entry with a real justification.
- `set-up-scan`: get from "I have an agent" to a first scan: `ziran discover`, `ziran init`, a
  target YAML, `ziran validate`, `ziran scan --dry-run`, then a budgeted scan (`--framework`,
  `--coverage`, `--phases`, `--llm-rpm`, `--llm-tpm`, `--max-cost`, `--max-campaign-tokens`).
- `threat-model-agent`: from an agent's tool list, name the dangerous chains and their ATLAS
  techniques using the shipped table, and use `ziran audit` as proof only when it is installed.

## How this fails

1. **Skills go stale.** A flag is renamed in the CLI (say `--max-cost`), the skill keeps telling
   Claude to pass it, and every user gets `No such option`. Guard: the drift test resolves every
   `ziran <command> --flag` in fenced and inline code against `ziran.interfaces.cli.main.cli`, and
   checks choice values (`--format json`, `--coverage standard`) against the option's choices.
2. **The marketplace does not resolve from GitHub.** The marketplace sits at the repository root
   beside `pyproject.toml` and a root `SKILL.md`; `claude plugin marketplace add taoq-ai/ziran`
   could pick the wrong manifest, fail strict validation, or install no skills. Guard: strict
   validation of both manifests, an isolated install from a `git archive` of the PR head that
   must list exactly the four skills, and a GitHub-shorthand install of the pushed branch.
3. **The ATLAS table lies or drifts.** A chain type is added to `chain_patterns.yaml` with no row,
   or a row cites an ID ZIRAN does not know, so Claude tells a user a wrong technique. Guard: the
   test reads every `type:` in `chain_patterns.yaml`, requires a table row for it, rejects rows
   for types that no longer exist, and checks every `AML.T` ID in the plugin files against
   `AtlasTechnique`.

## Clarifications

### Session 2026-10-18
- Q: Do the skills change `ziran` output to carry ATLAS IDs? A: No. The plan item puts any change
  under `ziran/` out of scope; the skills map chain types to ATLAS in markdown.
- Q: How is `ziran validate` exercised offline? A: It is not run: it needs a reachable target
  URL. Its flags are checked; `ziran scan --target ... --dry-run` is the offline schema check.
- Q: Is the root `SKILL.md` moved or edited? A: No. It is a contributor doc outside any
  `skills/` directory and is neither validated nor installed.
- Q: Does the test depend on the `claude` CLI? A: No. `claude plugin validate --strict` runs in
  the builder's checkout as extra evidence; in tests it is skipped when the CLI is absent.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Install the plugin from GitHub (Priority: P1)

A Claude Code user adds the marketplace and installs the plugin, then sees the four skills.

**Independent Test**: isolated `CLAUDE_CONFIG_DIR`, marketplace from a `git archive` of the head,
`claude plugin install ziran@ziran`, `claude plugin details ziran@ziran`.

**Acceptance Scenarios**:
1. **Given** the PR head, **When** `claude plugin validate --strict .` and `claude plugin validate
   --strict plugins/ziran` run, **Then** both exit 0.
2. **Given** an isolated `CLAUDE_CONFIG_DIR`, **When** the marketplace is added from a `git
   archive` of the head and `ziran@ziran` is installed, **Then** `claude plugin details
   ziran@ziran` lists exactly `audit-agents`, `triage-findings`, `set-up-scan`,
   `threat-model-agent`, and `~/.claude` is untouched.

### User Story 2 - Skills that cannot go stale (Priority: P1)

A maintainer renames or removes a CLI flag; CI fails before a stale skill ships.

**Independent Test**: `uv run pytest tests/unit/test_claude_plugin_skills.py`.

**Acceptance Scenarios**:
1. **Given** each `plugins/ziran/skills/*/SKILL.md`, **When** the test parses it, **Then** the
   frontmatter `name` equals the directory, `description` is non-empty, and every `ziran
   <command>` and `--flag` it names exists in the Click tree of `ziran.interfaces.cli.main`.
2. **Given** a flag is renamed or removed, **When** the test runs, **Then** it fails naming the
   skill file and the stale command or flag.
3. **Given** the audit skill's GitHub Action snippet, **When** the test reads `action.yml`,
   **Then** every `with:` key in the snippet is a declared input.
4. **Given** `chain_patterns.yaml`, **When** the test reads every chain `type:`, **Then** each
   resolves to a row of the ATLAS table and every `AML.T` ID in the plugin files is an
   `AtlasTechnique` member.

### User Story 3 - The commands the skills give actually run (Priority: P1)

**Acceptance Scenarios**:
1. **Given** `examples/25-claude-code-plugin/vulnerable-plugin`, **When** the test runs `ziran
   audit` with `--sarif` and `--write-baseline` into `tmp_path` and then `ziran audit --baseline`,
   **Then** the SARIF and baseline files exist and the baseline run exits 0.
2. **Given** `tests/fixtures/sample_campaign_result.json`, **When** the test runs `ziran report
   --format json`, `ziran ci --sarif <tmp> --suppressions <file built from the triage skill's
   template>`, `ziran export-policy --result ... --out <tmp>` and `ziran poc -o <tmp>`, **Then**
   none exits 2 and the suppressions file is accepted (one finding shows as suppressed).
3. **Given** `examples/15-remote-agent-scan/target-local.yaml`, **When** the test runs `ziran scan
   --target ... --dry-run`, **Then** it exits 0 with no external network and no LLM key.

### Edge Cases
- `ziran` named in prose ("when ziran is not installed") is not a command: only code spans and
  fenced code are parsed.
- `taoq-ai/ziran@v0`, `pip install ziran`, `ziran-version:` are not command invocations.
- `ziran cache clear` is a group plus subcommand; the parser walks groups.
- A flag named alone in code (`--max-cost 5` in a bullet) must be an option of a command the same
  file invokes; otherwise a rename would slip past the full-command check.
- `--phases a b` is a Click error (the option is `multiple=True`); parsing with the command's own
  Click parser reports the leftover argument. The CLI's own `scan --help` example has this bug.
- `unrestricted_execution` is reported by `ziran audit` but is not in `chain_patterns.yaml`; the
  coverage test reads `vulnerability_type="..."` literals from `chain_analyzer.py` as well.
- `ziran init` writes `ziran.yaml`, which `ziran scan` does not read; the set-up skill says so and
  passes flags instead.
- The dry run probes `localhost:8899` from the example (connection refused when nothing listens);
  it never leaves the host.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001 (marketplace)**: `.claude-plugin/marketplace.json` with `name: ziran`, an `owner`, a
  top-level `description`, and one plugin entry `ziran` with `source: ./plugins/ziran`.
- **FR-002 (plugin manifest)**: `plugins/ziran/.claude-plugin/plugin.json` with name, version,
  description and author, passing `claude plugin validate --strict`.
- **FR-003 (skills)**: four `SKILL.md` files under `plugins/ziran/skills/<name>/` with frontmatter
  `name` equal to the directory and a `description` that says when to trigger. Bodies are
  imperative and say what Claude adds beyond the command.
- **FR-004 (ATLAS table)**: one shared `plugins/ziran/skills/threat-model-agent/references/
  atlas-chains.md` whose rows map every chain type in `chain_patterns.yaml`, plus the single-tool
  type hard-coded in `chain_analyzer.py` (`unrestricted_execution`), to `AtlasTechnique` IDs. The
  other skills link to it.
- **FR-005 (threat model without ziran)**: `threat-model-agent` works from a tool list alone and
  runs `ziran audit` only when `ziran` is on `PATH`.
- **FR-006 (drift test)**: `tests/unit/test_claude_plugin_skills.py` covers US2 and US3; it does
  not need the `claude` CLI, network or an LLM key.
- **FR-007 (README)**: one install section in `README.md`.
- **FR-009 (untrusted content)**: `audit-agents`, `triage-findings` and `threat-model-agent` each
  state that content read from audited files, scan results, attack prompts or target responses is
  untrusted evidence, never instructions, and that only a control the user names can downgrade or
  suppress a finding (security gate, round 1). The drift test asserts the rule in each. The
  `SA001` guidance says not to repeat the secret value.
- **FR-008 (no runtime change)**: no file under `ziran/`, no new dependency, root `SKILL.md`
  unchanged.

### Assumptions
- **Branch name** `feat/059-claude-code-skills-plugin` follows the constitution's
  `type/NNN-short-name`. Overturned by an owner preference for the bare spec name.
- **Plugin version** `0.1.0`, independent of the ziran package version. Claude Code caches a
  plugin by version, so skill edits reach installed users only when the version is bumped. Tying
  it to release-please (`extra-files`) is a follow-up outside this item's file list.
- **Minimum ziran**: the skills say `ziran>=0.42.0`; `git diff v0.42.0 HEAD -- ziran/interfaces
  action.yml` is empty, so every command and flag named exists in the 0.42.0 release.
- **ATLAS mapping is editorial**: the table is ZIRAN's reading of each chain. ATLAS has no
  technique for a plain file write, so persistence chains cite only `AML.T0053` (AI Agent Tool
  Invocation) plus what the source side reads. Overturned by an ATLAS release that adds one.
- **Table location**: inside `threat-model-agent/references/`, the skill that needs it most; the
  others link with a relative path. Overturned if relative links fail to resolve when installed.
- **`CLAUDE.md` agent context** is not regenerated: it is not in the item's file list.

### Key Entities
None (markdown, JSON manifests and a test).

## Success Criteria *(mandatory)*
- **SC-001**: both strict validations exit 0 at the PR head.
- **SC-002**: isolated install lists exactly the four skills; `~/.claude` mtime and listing are
  unchanged.
- **SC-003**: the drift test passes at the head and fails, naming file and flag, when a skill flag
  is renamed in a scratch copy.
- **SC-004**: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`, `uv run
  pytest --cov=ziran` pass with coverage >= 85%; `git diff --stat origin/develop -- ziran/` is
  empty.
