# Goals

One block per goal. The plan's items each name the goal they serve.

## G-1
Outcome: ziran ships a Claude Code plugin with four skills (audit-agents, triage-findings, set-up-scan, threat-model-agent) that drive the ziran CLI and tag findings with MITRE ATLAS IDs.
Measure: skills present in the repo, installable via a plugin marketplace entry, with a CI test that runs every skill's commands against examples/.
Target: one PR to develop with all four skills, green CI (ruff, mypy strict, pytest >=85% coverage).
Date: 2026-10-25
Priority: 1

## G-2
Outcome: ziran v0.43.0 ships the ecosystem batch: OpenAI Agents SDK adapter (#392), AutoGen adapter (#285), Langfuse live trace pull (#287), MCP server-initiated attack surface (#394).
Measure: each of #392, #285, #287, #394 closed by a merged PR to develop with green CI; then v0.43.0 cut.
Target: four PRs to develop, green CI (ruff, mypy strict, pytest >=85% coverage), release v0.43.0.
Date: 2026-12-02
Priority: 1

## G-3
Outcome: the attack library and CVE ground truth cover agent/LLM/MCP attack techniques and CVEs published up to 2026-11.
Measure: new attack vectors (each with a source reference) for techniques published since the library's last update, and CVE-modeled ground-truth agents for agent/MCP CVEs published since the last addition; benchmark coverage docs regenerated.
Target: PRs to develop with green CI, shipped in v0.43.0.
Date: 2026-12-02
Priority: 2

## G-4
Outcome: ziran raises fewer false positives with no loss in detection.
Measure: the detection accuracy benchmark (spec 021, benchmarks/results/baseline.json) shows a lower false positive rate than today's baseline with recall equal or higher; the benchmark PR gate stays green.
Target: PRs to develop with green CI, shipped in the first release after merge (v0.43.0 is cut 2026-12-02 with whatever G-4 work has merged).
Date: 2026-12-09
Priority: 2

## G-5
Outcome: PR benchmarks and repo hygiene follow-ups from the v0.43.0 batch are closed, and the next build candidates are chosen from the open issues and the public roadmap.
Measure: the Benchmark Coverage workflow keeps one current PR comment instead of a new one per push; the last open Dependabot alert (langgraph, via #481) is closed; docs counts (roadmap.md) and the autogen extra match the code; a ranked candidate list drawn from open issues and docs/community/roadmap.md is in the plan.
Target: small PRs to develop with green CI, WIP 1.
Date: 2026-12-09
Priority: 1

## G-6
Outcome: the web UI leaves the free ziran package (tracking issue #520); it continues in ZIRAN Cloud and ZIRAN Enterprise. ziran stays the scanner: CLI, library, GitHub Action, Claude Code plugin, CI gate, SARIF and the self-contained HTML/Markdown/JSON reports.
Measure: #520's acceptance: the next release has no `ui/`, no `ziran/interfaces/web/`, no `ui` extra and no Node.js in the build or CI; all quality gates pass; the release note is in the GitHub release and CHANGELOG. #521, #522 and #523 all merge into develop before the next release is cut.
Target: PRs to develop for #521, #522, #523, released together as one breaking release with the announcement.
Date: 2026-12-09
Priority: 1
