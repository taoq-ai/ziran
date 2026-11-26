# Spec 125: `ziran audit` reads Agent Skills folders

**Status**: Active

## Promise (in my words)

`ziran audit` finds Agent Skills (`<dir>/SKILL.md` with frontmatter) in a plugin or project tree and audits each one as a skill, not as a subagent. A skill's tools are its `allowed-tools` pre-approvals; a skill without the key grants nothing, so it gets no `SA007` and no chain. Grants it does make go through the existing rules (`SA003`, `SA004`, `CC001`, `LT001`) with no rule or pattern change. Every file the skill bundles is inventoried: Python files go through the existing `StaticAnalyzer`, other scripts are reported as bundled and not analysed (never as clean). Skill findings carry the ATLAS technique the repository knows for this surface.

## Acceptance

- Given a plugin with `skills/exfil/SKILL.md` (`allowed-tools: Bash`) and a bundled script that reads `~/.aws/credentials` and posts it, when `ziran audit` runs, then the skill, its script and the dangerous tool are reported.
- Given a `SKILL.md` with no `allowed-tools`, when `ziran audit` runs, then it reports no `SA007` and no chain for that skill.
- Given a malformed `SKILL.md`, when `ziran audit` runs, then `CC000` names the skill and the reason, and the audit continues.
- Given `scripts/send.sh`, when `ziran audit` runs, then it is listed as bundled and not analysed, never clean.

## Behaviour

- Discovery: `root/skills/*/SKILL.md`, `root/.claude/skills/*/SKILL.md`, the manifest's `skills` paths (a skill folder, or a folder of skill folders), `root` when it is named `skills`, `root` itself when it holds a `SKILL.md`, and a `SKILL.md` given as PATH. A `SKILL.md` counts only when its first line is `---` (as for agent files); others are skipped silently. Duplicates drop by resolved path.
- Frontmatter keys read: `name` (default: the folder name), `description`, `model`, `allowed-tools` (split as the agent `tools` line is). A skill's `tools` key is not read.
- Rules on a skill reuse the agent rules with the message prefix `Skill '<name>'`. No `allowed-tools` key: no `SA007`, no `CC001`, no `LT001`. `allowed-tools: "*"` alone keeps `SA007` (it pre-approves every tool).
- Bundled files: every regular file under the skill folder except `SKILL.md`, walked without following symlinks. Kind `python` (`.py`), `script` (a script suffix, the executable bit, or a `#!` first line) or `other`. `python` files run through `StaticAnalyzer.analyze_file`; their findings carry the skill name. Each `script` gets one `CC002` (low) row. `other` files are inventoried only.
- Bounds, each a `CC000` row and the audit continues: a file or symlinked folder that resolves outside the audited root, a Python file over 1 MiB, more than 1000 bundled files, folders nested deeper than 8 levels, a non-regular file, a YAML or JSON document nested too deep to parse (this also guards agent files, `plugin.json` and `hooks.json`).
- In a directory audit, the Python pass skips files inside a parsed skill folder; the skill audit analyses them once.
- ATLAS: every skill row (including bundled-file rows) carries `atlas: ["AML.T0110"]` (AI Agent Tool Poisoning) in JSON and in SARIF result properties. Other rows gain no key.
- Baseline (`--baseline`): skills are not in the baseline schema; skill rows pass through unchanged and never count as accepted.

## Out of scope

AI-BOM entries for skills (F-AIBOM-SCAN; `build_aibom` reads `scan.agents` only, and `scan.skills` is where it would read them). Shell or JavaScript analysis, Cursor, VS Code, Codex or Gemini configs, Claude Code `commands/`. No new chain rules or patterns (paper freeze).

## Assumptions

- AML.T0010.005 and AML.T0104, named in the item, are not in the repository's ATLAS data (`AtlasTechnique` has neither; `git grep` finds 0). They are not added here; only AML.T0110 is mapped. Overturned if the ATLAS enum gains them (a separate data change).
- `CC002` is low: it reports a gap in coverage, not a found weakness. It still keeps the report from reading "No issues found". Overturned if the owner wants unanalysed scripts to fail `--severity medium`.
- A malformed `SKILL.md` yields only its `CC000`; its bundled files are then left to the plain Python pass. Overturned if a malformed skill's scripts must be listed too.
- A skill with no `allowed-tools` grants nothing (Claude Code docs: the key pre-approves tools and does not restrict them).
