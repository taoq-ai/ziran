# Implementation Plan: Unreached tag warning

**Spec**: [spec.md](spec.md)

## Technical context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13); stdlib only, no new dependencies.

## Design

- `ResultBuilder._unreached_tags_warning(radii)` in
  `ziran/application/agent_scanner/result_builder.py`: collect node ids from every radius's
  `demonstrated.tags` and `reachable.tags`, add each id without `tool_`, and return one warning
  naming the configured keys outside that set, or none.
- `build` appends it after `graph.warnings` into `metadata["warnings"]`.
- No renderer change: `reports.py` and `html_report.py` already print `result.warnings`.
- `docs/reference/cli.md` gains one sentence.

## Constitution check

Application layer only; module stays under the 400-line budget (`test_scanner_size.py`).
