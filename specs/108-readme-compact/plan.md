# Plan: a compact engine README that points to the docs site

Docs only. No source, test or dependency change.

1. Map each README section to a docs page (table in `spec.md`). Move what is missing first:
   `docs/index.md` gains "How It Works" and "Citation" and takes the newer comparison table;
   `docs/getting-started.md` gains the `pentest` and `otel` extras, Docker and the report
   image, and its Python API example uses the adapter's real `agent=` keyword;
   `docs/guides/claude-code.md` gains the plugin install.
2. Rewrite `README.md` to the sections the item names, under 120 lines.
3. Check: `mkdocs build --strict` gives no warning beyond the 7 develop already has; every
   README docs link resolves to a built page and anchor; every repository-relative link points
   to an existing file.
