# Tasks: a compact engine README that points to the docs site

Base: `origin/develop` at d1fa050. Branch `docs/108-readme-compact`. Docs only, no test.

- [x] T001 Move "How it works", the comparison table and the citation to `docs/index.md`.
- [x] T002 Add the `pentest` and `otel` extras, Docker and the report image to
  `docs/getting-started.md`; fix its `LangChainAdapter(agent=...)` keyword.
- [x] T003 Add the Claude Code plugin install to `docs/guides/claude-code.md`.
- [x] T004 Rewrite `README.md`: 329 lines to 97.
- [x] T005 `mkdocs build --strict`: the same 7 warnings as develop, none new. Every README link
  checked against the built site and the tree.
