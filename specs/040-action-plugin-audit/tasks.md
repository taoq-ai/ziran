# Tasks: run Claude Code plugin audits from the ZIRAN GitHub Action

Prerequisite: #419 (`039-audit-allowlist-baseline`) merged into `develop`; rebase this branch onto
it before T003 (it provides `--baseline` / `--write-baseline` and the `BL00x` rows). T001-T002 only
need #418, which is already on `develop`.

Test-first: every implementation task is preceded by a test task that MUST be run and seen failing
before the implementation lands. For `action.yml` and the workflows, the failing test is the
contract test (T005) and the CI job (T007), which must be seen red on the PR before T008 (or run
against the unmodified `action.yml` first). No network, no LLM in pytest. The contract is
[plan.md §Public contract](plan.md#public-contract).

## Phase 1 — SARIF for audit rows (FR-002)

- [x] T001 [US1][US4] Failing tests, new class `TestAuditSarif` in `tests/unit/test_cicd.py`
      (in-memory `StaticFinding`s, `monkeypatch.chdir(tmp_path)`):
      - envelope: `version == "2.1.0"`, one run, driver `name == "ZIRAN"`, same `$schema` as
        `generate_sarif`;
      - a `BL001` critical row with `agent="builder"`, `tools=("WebFetch",)`,
        `file_path="plug/agents/builder.md"`, `line_number=4` -> result `ruleId "BL001"`,
        `level "error"`, message verbatim, uri `plug/agents/builder.md`, `uriBaseId "%SRCROOT%"`,
        `region.startLine == 4`, `properties == {"agent": "builder", "tools": ["WebFetch"]}`;
      - level map: `high` -> `error`, `medium` -> `warning`, `low` -> `note`;
      - a Python row (`agent=None`, `line_number=None`, `context="sk-secret-value"`) -> no
        `properties`, no `region`, and `"sk-secret-value"` absent from `json.dumps(doc)`;
      - absolute path under cwd -> relative POSIX uri; absolute path outside cwd -> `file://` uri,
        no `uriBaseId`;
      - two `CC001` rows (`high`, then `critical`) -> one rule, `security-severity == "9.0"`,
        `defaultConfiguration.level == "error"`, results keep their own levels, report order kept;
      - rule `help.text` is the first non-empty recommendation; omitted when none;
      - `[]` -> `results == []`, `rules == []`;
      - existing `TestSarif` passes unchanged (envelope refactor is byte-neutral).
- [x] T002 [US1][US4] Implement `generate_audit_sarif` and `_sarif_document` in
      `ziran/application/cicd/sarif.py`; refactor `generate_sarif` to use `_sarif_document`
      (plan §1). T001 green.

## Phase 2 — `ziran audit --sarif` and the sample plugin (FR-001, FR-007)

- [x] T003 [US1][US2][US3][US4] Failing tests, new class `TestAuditSarif` in
      `tests/unit/test_cli_main.py` (no markers; `CliRunner`, `monkeypatch.chdir(tmp_path)`,
      sample copied with `shutil.copytree` from `examples/07-cicd-quality-gate/claude-code-plugin`):
      - sample + committed baseline, `--format json`: exit `0`, `findings == []`;
      - `--write-baseline tmp_path/b.json` on the sample: bytes equal the committed
        `ziran-baseline.json` (drift guard);
      - copy widened (`, WebFetch` appended to line 4 of `agents/builder.md`),
        `ziran audit plug --baseline plug/ziran-baseline.json --sarif out.sarif`: exit `1`,
        `out.sarif` has `BL001` (message `"Agent 'builder' gains tool 'WebFetch' not in the
        baseline"`, uri `plug/agents/builder.md`, `startLine 4`) and `BL003` (message
        `"Agent 'builder': new critical chain data_exfiltration via Read -> WebFetch not in the
        baseline"`);
      - same with `--format json`: stdout parses as one JSON document equal to the run without
        `--sarif`, `result.stderr` (Click 8.4 keeps it separate) holds
        `SARIF written to out.sarif`; SARIF `ruleId`s equal the JSON rows' `rule`s in order;
      - text mode (no `--format`): the SARIF file exists although the command exits `1`;
      - `--severity critical --sarif` on the widened copy: no `SA003` result in the SARIF;
      - narrowing (researcher drops `Glob`) with `--baseline --sarif`: exit `0`, SARIF
        `results == []`;
      - `--sarif tmp_path/missing-dir/x.sarif`: exit `2`, no traceback in output;
      - Python-only dir with `--sarif`: file written, results match the JSON rows.
- [x] T004 [US1][US2] Add the sample plugin files (plan §4) and record `ziran-baseline.json` with
      `ziran audit . --write-baseline ziran-baseline.json` from inside the sample directory; add the
      `--sarif` option and block to `audit` in `ziran/interfaces/cli/main.py` (plan §2), plus the
      docstring example. T003 green; all existing `audit` tests pass unchanged.

## Phase 3 — Action contract (FR-003..FR-005)

- [x] T005 [US1][US3] Failing test `tests/unit/test_action_yml.py` (`@pytest.mark.unit`, PyYAML
      `safe_load` of the repo-root `action.yml`):
      - inputs `path` and `baseline` exist with `default == ""`; every pre-existing input keeps its
        default (`command "ci"`, `source-path "."`, `sarif-output "ziran-results.sarif"`,
        `severity-threshold "low"`, `ziran-version "ziran"`, ...);
      - outputs `exit-code` (`steps.run.outputs.exit_code`) and `sarif-id`
        (`steps.upload.outputs.sarif-id`) exist; `status`, `trust-score`, `total-findings`,
        `critical-findings`, `sarif-file` unchanged;
      - the `run` step's `env` maps `ZIRAN_INPUT_PATH`, `ZIRAN_INPUT_SOURCE_PATH`,
        `ZIRAN_INPUT_BASELINE`, `ZIRAN_INPUT_SEVERITY`, `ZIRAN_INPUT_SARIF` to the inputs, and the
        `audit)` branch of its script contains no `${{ inputs.` text;
      - the upload step has `id: upload`.
- [x] T006 [US1][US3] Edit `action.yml` per plan §3. T005 green. Check the script locally with
      `bash -n` on the extracted `run` block (and `shellcheck` if installed).

## Phase 4 — CI acceptance and example (FR-006, FR-008)

- [x] T007 [US1][US2][US3] Add job `test-audit-claude-code-plugin` and the new `paths` entries to (job written and its bash/python assertions run locally against a simulated run step; first real run happens on the PR)
      `.github/workflows/action-test.yml` (plan §5). It is the end-to-end test: push it first with
      the T006 change reverted (or observe it red in a draft commit) to see it fail on the missing
      inputs, then with T006 and see it green. Assertions use bash `[ ]` and `python3` only.
- [x] T008 [US1] Add `examples/07-cicd-quality-gate/claude-code-audit.yml` (plan §4) and add it to
      the `templates` list in `.github/workflows/lint-ci-templates.yml`. Verify locally with
      `uv run python -c "import yaml; yaml.safe_load(open('examples/07-cicd-quality-gate/claude-code-audit.yml'))"`.

## Phase 5 — Docs (FR-009)

- [x] T009 [P] `docs/guides/ci-integrations.md`: subsection "Claude Code plugin audit" under GitHub
      Actions with the plan §3 contract summary, the inputs table rows (`path`, `baseline`,
      `sarif-output`), outputs (`exit-code`, `sarif-id`), exit codes `0`/`1`/`2`, permissions, and a
      link to the example; update the **Outputs** line.
- [x] T010 [P] `docs/reference/cli.md` (`ziran audit` options table, after #419's rows): `--sarif
      FILE`; `examples/07-cicd-quality-gate/README.md`: list `claude-code-audit.yml` and
      `claude-code-plugin/`.

## Phase 6 — Gates

- [x] T011 `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
      `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock` drift. Push, open the PR against
      `develop`, and wait for `gh pr checks` (including `Action Self-Test` and `Lint CI Templates`)
      to be green.
