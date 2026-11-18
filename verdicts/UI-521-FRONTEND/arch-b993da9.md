Verdict: PASS
Gate: arch
Item: UI-521-FRONTEND
PR: taoq-ai/ziran#526
Head: b993da94e9acfe83fb874454cc73c2343ca0cc46
Confidence: high
Breaking: yes: the repository Docker image no longer serves the web UI (CMD `ziran ui` on 8484 becomes ENTRYPOINT `ziran`, so `docker run <image> ziran <cmd>` now runs `ziran ziran <cmd>`), and `docker compose up` (db + ziran-ui) is gone; both are inside #520's announced UI removal (Announcement: #520, PR title `!`), and no published image or workflow consumes them

## Findings
- [low] README.md:236 blocks: no. The Web UI section still says `pip install ziran[ui]`, `ziran ui` and `docker compose up`; it has been stale since #525, and the spec gives README to UI-523, which should also add the CLI image usage (`docker build --build-arg ZIRAN_VERSION=... .`, `docker run ziran scan ...`).
- [low] Dockerfile:4 blocks: no. With no build arg the image reports `ziran, version 0+unknown`; no workflow builds or publishes an image today, but any future image publish job must pass ZIRAN_VERSION, the same way release.yml sets SETUPTOOLS_SCM_PRETEND_VERSION from the tag.
- [low] Dockerfile:7 blocks: no. The image installs the base package only, with no extras, so `scan --framework langchain|crewai|...` and the browser adapter need a derived image. Remote `scan --target` and `audit` work as-is. This is a limit, not a regression: the old image installed only `.[ui]`.

## Probes
- Build arg vs wheel: the build arg is the right minimal fix. `.dockerignore` excludes `.git` and `dist/`, so hatch-vcs needs SETUPTOOLS_SCM_PRETEND_VERSION, and installing a wheel would need a pre-built dist/ in the context (excluded) or a builder stage that has the same version problem. release.yml already uses the same env var. pyproject `readme = README.md` and `license-files = [LICENSE, NOTICE]` explain the added COPYs, and `.dockerignore` `!README.md` keeps README in the context.
- `git archive b993da9` into scratch sentinel-arch-UI-521/tree. `uv build` with Node off PATH (`which node` was empty inside) built the sdist and the py3-none-any wheel. `unzip -l` shows no static/, web/, .js, .css or index.html (the only matches are static_analysis/), and the sdist has no ui/, hatch_build or docker-compose.
- `podman build .` succeeded. `run --help` printed the ziran CLI help, `--version` printed `0+unknown`, `scan --help` works, and `run ui` prints the moved-to-Cloud message. Entrypoint [ziran], Cmd [], no ExposedPorts, WorkingDir /app. The default is usable: `docker run image scan ...` reaches the CLI.
- docker-compose dependents: `git grep -i 'docker-compose|docker compose|compose.yml'` at the head hits only README.md:238 (UI-523) and a benchmark fixture string (vulnerable_devops.yaml, unrelated). action.yml, .github/ and examples have no docker reference except examples/22 (a jaeger container, unrelated). Nothing else depends on the deleted file.
- Release workflow: the build job keeps the tag-pinned SETUPTOOLS_SCM_PRETEND_VERSION, `uv build`, the tag/version check and the dist/ upload, so it produces the same sdist and wheel minus the UI assets. publish-pypi, publish-testpypi and the GitHub Release upload are unchanged.
- Required checks: `gh api repos/taoq-ai/ziran/rulesets/12656045` (main-protection) requires lint, test (3.11/3.12/3.13) and typecheck; frontend-build is not among them. develop is unprotected (404).
- Fitness test: tests/unit/test_no_frontend_build.py at the head gave 15 passed (timeout 120). Mutant (fresh copy sentinel-arch-UI-521/mut): re-adding `[tool.hatch.build.hooks.custom]` and an `actions/setup-node` step to release.yml made 2 tests fail (test_frontend_sources_and_build_hook_are_gone, test_no_workflow_step_needs_node_or_ui[release.yml]).
- Conformance: no Python under ziran/ changed, so the constitution's hexagonal rules are not touched. Remaining Node references are the promptfoo docs/examples (third-party CI, unrelated) and static_analysis' node_modules exclusion.
- Old Dockerfile build: not run. By reading, it copied neither README/LICENSE/NOTICE nor .git, so hatchling and hatch-vcs could not have built it, and it installed `.[ui]`, which #525 removed. The ENTRYPOINT break therefore hits an image that was not buildable at the base.
- Confidence high: the wheel, the image and the workflows were exercised at the head. Only a published-image consumer outside the repo could change this, and I found none.

## Residual risk
External users who built the image themselves before #525 and scripted `docker run img ziran ...` will break. That is covered by the #520 migration note in the PR body, and UI-523 must carry the same note into the README.
