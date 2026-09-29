# Tasks: Recognise Claude Code tool calls in OTel traces

Prerequisite: #417 (`033-claude-code-chain-patterns`) merged into `develop`; rebase this branch on
it before T005 (it provides `canonical_tool_name` and the `unrestricted_execution` finding).

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. No network, no LLM. Unit tests `@pytest.mark.unit`, CLI tests
`@pytest.mark.integration`. Fixture values are fake; never use `AKIA`/`sk-` lookalikes.

## Phase 1 — Session grouping + unreadable input (FR-002, FR-003)

- [ ] T001 [US1][US2] Failing tests in `tests/unit/test_otel_ingestor.py` (write JSONL to
      `tmp_path` inline; helper that builds one ResourceSpans line):
      - spans with different `traceId` and the same span attribute `session.id` -> one session,
        `session_id == <session.id>`, calls ordered by `startTimeUnixNano`;
      - two `session.id` values sharing one `traceId` -> two sessions;
      - `session.id` only on the resource -> used as the key; span attribute wins over resource;
      - span with `session.id` but no `traceId` -> kept; span with neither -> skipped;
      - non-empty file where every line is invalid JSON -> `ValueError`;
      - empty file -> `[]`;
      - all existing tests in the file pass unchanged (traceId fallback).
- [ ] T002 [US1][US2] Implement plan §1 in `ziran/infrastructure/trace_ingestors/otel_ingestor.py`
      (`_process_batch` key order, `ingest` all-malformed `ValueError`, docstrings). T001 green.

## Phase 2 — Redaction, Bash evidence, aggregation (FR-004..FR-007)

- [ ] T003 [US3] Failing tests in `tests/unit/test_analyzer_service.py` for `redact_secrets`
      (parametrized; each secret value MUST be absent from the output and `[REDACTED]` present):
      `Authorization: Bearer abc.def-123`, `export OPENAI_API_KEY=sk-` + 24 x `a` (SA001),
      `password = "hunter2hunter2"` (SA001 quoted), `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENG`,
      `API_KEY=ziran-fake`, `--token=abc123`, `--password hunter2`,
      `git push https://user:p4ssw0rd@github.com/o/r`; unchanged: `git status`, `ls -la /repo`,
      `pytest -q tests/`.
- [ ] T004 [US3] Implement `redact_secrets` + cached `_secret_patterns` in
      `ziran/application/trace_analysis/analyzer_service.py` (plan §2; SA001 via
      `StaticAnalysisConfig.default()`, plus the command-line rules). T003 green.
- [ ] T005 [US1][US3] Failing tests in `tests/unit/test_analyzer_service.py` (use `_make_session`,
      extended with an optional per-call `arguments` list):
      - `["Read", "WebFetch"]` session `s1`: the critical chain has
        `evidence["sessions"] == [{"session_id": "s1", "commands": []}]` and keeps `edge_exists`;
      - `["Read", "Bash"]` with Bash `{"command": "curl -H 'Authorization: Bearer tok-123' x"}`:
        the `["Bash"]` `unrestricted_execution` finding's `evidence["sessions"][0]["commands"]`
        is one string containing `[REDACTED]` and not `tok-123`;
      - 12 Bash calls -> 10 commands; a 2 000-char command -> 500 chars;
      - a shell call whose tool is not in `chain.tools` contributes nothing; a Bash call without a
        string `command` contributes nothing;
      - same `["Read", "WebFetch"]` chain in sessions `s1` and `s2` -> one aggregated chain whose
        `evidence["sessions"]` lists both session ids (`occurrence_count == 2` still holds);
      - reported `tools` are verbatim (`["Read", "WebFetch"]`), never canonical keywords.
- [ ] T006 [US1][US3] Implement `_shell_commands`, the `evidence["sessions"]` assignment in
      `_analyze_session`, and the `setdefault(...).extend(...)` merge in `_aggregate_chains`
      (plan §2; import `canonical_tool_name` from `ziran.application.knowledge_graph.tool_aliases`).
      T005 green; all pre-existing tests in `test_analyzer_service.py` pass unchanged.

## Phase 3 — Fixtures, CLI exit codes, issue acceptance (FR-008, FR-009)

- [ ] T007 [US1][US3] Add the four fixtures under `tests/fixtures/claude_code_traces/` exactly as in
      plan §4 (contract v1 fields, fake values, per-line `traceId` differences / sharing as noted).
- [ ] T008 [US1][US3][US4] Failing tests in `tests/integration/test_analyze_traces_cli.py`
      (`--source otel --format json --out tmp_path`):
      - `read_env_then_webfetch.jsonl` (issue acceptance): exit `1`; report has a chain with
        `tools == ["Read", "WebFetch"]`, `risk_level == "critical"`, `vulnerability_type ==
        "data_exfiltration"`, `evidence.sessions[0].session_id == "cc-session-exfil"`;
        `critical_chain_count >= 1`; `metadata.sessions_analyzed == 1`;
      - `read_then_grep.jsonl`: exit `0`, `dangerous_tool_chains == []`;
      - `two_sessions.jsonl`: exit `0`, `metadata.sessions_analyzed == 2`, no chains;
      - `bash_with_secret.jsonl`: exit `0` (only `high`); the `Bash` finding's commands contain
        `[REDACTED]`; neither `ziran-fake-token-0001` nor `ziran-fake-key-0002` appears in any file
        under `tmp_path` (walk `rglob("*")`) nor in `result.output`;
      - `--format markdown` over `read_env_then_webfetch.jsonl`: exit `1`;
      - exit `2`: missing `--input` path, `--input` a directory, non-empty all-garbage file,
        `--source otel` without `--input`, `--alert` without `--config`; output has `Error` and no
        `Traceback`;
      - update existing expectations: `test_otel_json_output`, `test_otel_markdown_output`,
        `test_verbose_flag`, `test_finds_dangerous_chains_in_otel` and `test_langfuse_file_mode`
        run critical sample fixtures -> `exit_code == 1` (was `0`); `test_otel_requires_input`
        -> `exit_code == 2`.
- [ ] T009 [US4] Implement plan §3 in `ziran/interfaces/cli/analyze_traces.py` (try/except ->
      `2`, usage errors -> `2`, critical -> `1` after report + alerts). T008 green; run
      `tests/integration/test_analyze_traces_alerting.py` unchanged and green.

## Phase 4 — Docs (FR-001, FR-008, FR-009)

- [ ] T010 [US2] Update `docs/guides/analyze-traces.md` per plan §5: "Claude Code span contract
      (version 1)" (field table, `session.id` grouping, compatibility rule, example line identical
      to line 1 of `tests/fixtures/claude_code_traces/read_env_then_webfetch.jsonl`), "JSON output"
      field list, "Exit codes" table replacing the old bullet, `Bash` evidence/redaction note.
      Verify with `diff <(sed -n 1p tests/fixtures/claude_code_traces/read_env_then_webfetch.jsonl)
      <(<extract example line from the doc>)` by hand; `uv run mkdocs build --strict` if mkdocs is
      available locally.

## Phase 5 — Gates

- [ ] T011 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock` drift. Commit as
      `feat(traces): ...` / `test(traces): ...` / `docs(traces): ...` with no `!` and no
      `BREAKING CHANGE` footer (see plan "Release note"); no `Co-Authored-By` trailer. PR targets
      `develop`; PR body states the exit-code change and lists the JSON fields for WUWEI #34.
