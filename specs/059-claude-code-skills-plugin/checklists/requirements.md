# Requirements checklist: ziran Claude Code plugin with four skills and a CLI drift test

- [x] CHK001 Each functional requirement maps to an acceptance scenario or task (FR-001/002 US1.1,
      FR-003 US2.1, FR-004 US2.4, FR-005 skill step 5, FR-006 US2 and US3, FR-007 T005, FR-008
      SC-004).
- [x] CHK002 Every plan-item acceptance line has a test or a recorded manual check (strict
      validate and isolated install are manual plus a skip-if-absent test; the rest are pytest).
- [x] CHK003 The test needs no `claude` CLI, network beyond localhost, or LLM key.
- [x] CHK004 No file under `ziran/` changes; root `SKILL.md` unchanged; no new dependency.
- [x] CHK005 Each skill has a `name` equal to its directory and a `description` that says when to
      trigger.
- [x] CHK006 Each skill says what Claude adds beyond the command (interpretation, fix, justified
      suppression), not only a command list.
- [x] CHK007 `threat-model-agent` works without ziran and runs `ziran audit` only when installed.
- [x] CHK008 The ATLAS table covers every chain type ZIRAN reports, including
      `unrestricted_execution`, and cites only `AtlasTechnique` IDs.
- [x] CHK009 The skills tell users to scan only agents they are authorised to test and never to
      write a token into a target file.
- [x] CHK010 Each "How this fails" item has a guard that a scratch mutation proved (flag rename,
      command removal, chain type rename, unknown ATLAS ID, undeclared action input, bad
      suppressions key).
