# Requirements checklist: append sql_query and python_repl to send_email chain patterns

- [x] Each functional requirement has an acceptance scenario or task (FR-001 US1.1, FR-002
      US1.2, FR-003 US2, FR-004 task T003, FR-005 SC-003).
- [x] Both types already exist in the library (`database_exfiltration`, `repl_exfiltration`).
- [x] The patterns are appended after every existing pattern; none is edited or moved.
- [x] The spec states that both patterns are post-hoc for the ziran-paper study.
- [x] Tests use only synthetic in-memory graphs.
- [x] Dev recall scores, prints and inspects no held-out scenario; the parse of held-out files
      by `dev_benchmark.py` is recorded in the spec's study note.
- [x] No new dependency.
