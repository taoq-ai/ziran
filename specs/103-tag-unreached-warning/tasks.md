# Tasks: Unreached tag warning

- [x] T001 Tests first in `tests/unit/application/test_blast_radius_report.py` (`TestUnreachedTags`): a tag on a tool outside every chain is named (result, Markdown, HTML); reached tags by id and name are not; no tags means no warning. Run red.
- [x] T002 `ResultBuilder._unreached_tags_warning` and its use in `build`. Run green.
- [x] T003 One sentence in `docs/reference/cli.md`.
- [x] T004 ruff, format, mypy, touched tests and `test_scanner_size.py`.
