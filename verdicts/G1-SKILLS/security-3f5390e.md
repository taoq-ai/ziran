Verdict: PASS
Gate: security
Item: G1-SKILLS
PR: taoq-ai/ziran#470
Head: 3f5390ed519c5d66c868310beb162f8e3446cefa
Confidence: medium

## Findings
- [low] plugins/ziran/skills/set-up-scan/SKILL.md:30 blocks: no. OWASP LLM01 class, a remaining gap. The skill has Claude summarise the tools that `ziran discover --target` returns from a remote HTTP, MCP or A2A endpoint. Tool names and descriptions from a third-party endpoint are text an attacker can control, and this skill does not carry the untrusted-content rule. The exposure is smaller than in the round-1 finding: the output only feeds the choice of scan phases, not a decision to dismiss a finding, and the target is normally the user's own agent. One sentence pointing at the same rule would close it.
- [low] plugins/ziran/skills/audit-agents/SKILL.md:96 blocks: no. CWE-829 class, carried from round 1 with no change. The workflow snippet pins `taoq-ai/ziran@v0`, a moving tag, in a job that has `security-events: write`. `ziran-version` is pinned exactly.
- [low] blocks: no. Carried from round 1. The dry-run test sends a request to the existing demo fixture at localhost:8899 with the token "demo-token". Only loopback is reached.

## Probes
- The round-1 blocking finding is closed. I read `git diff c3949f8 3f5390e`: 6 files changed. An "Untrusted content" paragraph now sits right after "read the agent's prompt" in audit-agents (lines 47-50), after the result-file read in triage-findings (lines 28-32, which also says attack prompts are injection payloads and responses come from the target under attack), and after the tool-inventory step in threat-model-agent (lines 21-24). Each paragraph forbids downgrading, dismissing or suppressing a finding because the content claims to be safe, and says only a control the user names counts. That matches the fix the round-1 verdict asked for.
- The SA001 row (audit-agents:40) now says "Cite file and line; never repeat the secret value". That closes the round-1 CWE-532 note.
- The delta touches only skill markdown, the spec and tasks files, and the test. Nothing under ziran/, .github/, pyproject.toml, uv.lock or action.yml changed, and no hook, .mcp.json or `allowed-tools` was added, so the plugin's privilege surface is the same as round 1.
- Drift test in a git-archive copy at 3f5390e (uv sync with SETUPTOOLS_SCM_PRETEND_VERSION): 24 passed. With `-m "not integration"`, as CI runs it: 22 passed and 2 deselected. The 2 deselected are the claude-CLI validate tests, now marked `integration`. That marker is registered in pyproject.toml under `--strict-markers`, and test.yml:69 runs `-m integration` in a separate job.
- Mutants: in three fresh copies I deleted the Untrusted-content paragraph from one skill each. `test_skill_treats_read_content_as_untrusted[<skill>]` failed for each, 1 failed and 2 passed per copy.
- CI, read once with `gh pr checks 470`: lint, typecheck, dependency-audit, CodeQL (actions, javascript-typescript, one python run), frontend-build, detection-accuracy-gate and pentest-eval-gate pass. test (3.11/3.12/3.13), integration-test and one CodeQL python analysis were still pending at the time I read them, so they are unmeasured here. The repository has no secret scanner, so secret scanning is unmeasured.
- Why confidence is medium: the fix is an instruction to a model. I did not run an end-to-end Claude session against a hostile agent file, so the rule's effect on model behaviour is not measured.

## Residual risk
A model that reads hostile agent files or attack transcripts can still be steered despite the rule. The human-confirmation steps (the user agrees to the baseline; a finding is accepted only on a control the user names) remain the real backstop.
