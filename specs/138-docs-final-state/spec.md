# Spec 138: engine docs at the final state of develop

Status: Active. Docs only. Follows specs 116 to 137.

## Promise (in my words)

Every command and flag that specs 116 to 137 added has a correct entry in `docs/reference/cli.md`
and a concept or guide page where a user would look. The nav links the pages. Nothing in the docs
claims what the code does not do, and the docs hold no partner, customer, pricing or hosted
platform text.

## Acceptance

- `ziran --help` and each subcommand's `--help` (checked from this branch) match the CLI
  reference: all 16 commands are listed, and `scan`, `multi-agent-scan`, `export-policy`,
  `mcp-hostile-server`, `analyze-traces`, `pentest`, `init` and `validate` carry their flags.
- `ziran ci` documents goal gating on a result JSON and on a SARIF (spec 130).
- `--attacker-cassette` has a concept section (spec 132); skills audit, goals and trials have a
  guide section; shared attacker budget is in the long-running guide (spec 131).
- Guides that were in no nav entry (analyze traces, policy refresh, two benchmark pages) are linked.
- `tests/unit/test_doc_counts.py` passes.

## Assumptions

- The docs tests and a docs build are the checks; no code changes, so no code test. Overturned if
  a doc claim needs a test only code can hold.
- The commercial licence text in `README.md` is the owner's licensing notice, not a platform
  mention, so it stays.
- `require_owasp_coverage` is declared on the gate config and read nowhere, so the docs say
  required OWASP coverage is the `required_owasp` policy rule. A follow-up may remove the field.

## Rollback

Revert the merge commit; nothing but Markdown and `mkdocs.yml` changes.
