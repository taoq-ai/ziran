# Plan: spec 125

- Domain (`ziran/domain/entities/claude_code.py`): `ClaudeCodeSkillFile` (path, kind) and `ClaudeCodeSkill`, a `ClaudeCodeAgent` whose `tools` are its `allowed-tools`, with `bundled` files and no inherited tool set. `ClaudeCodeScan.skills`; `detected` counts skills.
- Loader (`ziran/infrastructure/config/claude_code_plugin.py`): the frontmatter parse moves out of `agent()` into a shared helper (also catching `RecursionError`); `skill()` builds the entity; `bundled()` walks the folder with the bounds of the spec. `load_claude_code` discovers skills and treats a found skill like a found agent for hooks and MCP reads.
- Audit (`ziran/application/static_analysis/claude_code_audit.py`): `declared_tools` returns `[]` for a skill without the key; `_audit_agent` takes the label from the entity; skill rows get `atlas`; bundled Python runs through `StaticAnalyzer(config).analyze_file`; scripts give `CC002`.
- `StaticFinding.atlas` (default `()`); JSON rows and SARIF results show it only when set. `StaticAnalyzer.analyze_directory(exclude=...)` skips files under the given folders.
- Baseline: `apply_baseline` keeps skill rows unchanged.
- CLI: pass the skill folders as `exclude`; help text and `docs/reference/cli.md`.
- No change to detectors, the hybrid judge, role typing, `tool_aliases`, `chain_patterns.yaml` or `ToolChainAnalyzer`.
