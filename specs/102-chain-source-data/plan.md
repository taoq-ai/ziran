# Plan: A chain's data classes include what its source tools reach

No new dependency.

- `ziran/application/agent_scanner/result_builder.py`: `_fill_blast_radius` groups the
  chains by last tool, collects the last tool and every source tool of those chains, and
  calls the existing `blast_radius()` once per group. Each chain gets its group's radius.
- `blast_radius()` already takes several start tools and dedups them, so the walk is
  unchanged. The result JSON keeps one radius per last tool.
- Docstrings: `blast_radius.py`, `BlastRadius` and `DangerousChain.blast_radius` in
  `ziran/domain/entities/capability.py`; the report intro in `ziran/interfaces/cli/reports.py`;
  `docs/reference/cli.md`.
- Frozen code untouched: detectors, hybrid, role typing, tool aliases, chain patterns and
  their matcher. `result_builder.py` is in `agent_scanner/`, so `test_scanner_size.py` runs.

Tests in `tests/unit/application/test_blast_radius_report.py` (`TestSourceTools`): a probe
shaped graph (only the dangerous tool links to `sensitive_data`, no edge to the readers) with
`read_inbox` tagged, reachable and demonstrated; the file-to-HTTP chain reads only `secret`;
a shared `sensitive_data` tag with an unrelated tagged tool adds no class; two chains with one
last tool share one walk and both sources' classes. The existing blast-radius tests stay as
they are.

Benchmarks and recorded fixtures: none in this repository hold a blast radius (`git grep -l
blast_radius -- benchmarks tests/fixtures` is empty), so none move.
