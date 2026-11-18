Verdict: PASS
Gate: security
Item: G5-AUTOGEN-EXTRA
PR: taoq-ai/ziran#517
Head: 2083c5067c6a02ded0d91d108d52722a5ad6c515
Confidence: high

## Findings
- [low] uv.lock:2 blocks: no. The lock `revision` goes from 5 to 3 because the builder ran an older uv. This is a format marker, not a dependency change, and it has flipped before between Dependabot and local relocks. The PR body says "nothing else" changed, which leaves this out.
- [low] blocks: no. Upstream autogen-ext 0.7.5 lists no project URLs in its PyPI metadata. Provenance comes from the PEP 740 attestation instead (see Probes).

## Probes
- Scope: `git diff --stat 80003bc 2083c50` (base = origin/develop) touches 4 files: pyproject.toml +1, uv.lock +24/-1, and two example READMEs.
- Lock: `uv lock --check` at the head (git archive copy) exits 0. The only new package is autogen-ext 0.7.5. aiofiles 24.1.0, openai 2.54.0, tiktoken 0.13.0, autogen-core 0.7.5 and autogen-agentchat 0.7.5 have the same versions in the base lock and the head lock, so the new transitive surface is autogen-ext alone. autogen-ext's base dependency is autogen-core==0.7.5.
- Hashes: the sha256 values from the PyPI JSON API for 0.7.5 match uv.lock exactly (wheel 18cecc8a..., sdist 711ab923...). I downloaded the wheel and ran `shasum -a 256`; it matches. Neither file is yanked, and the PyPI `vulnerabilities` list is [].
- Provenance: the PEP 740 attestations for both wheel and sdist name publisher GitHub `microsoft/autogen`, workflow `single-python-package.yml`, environment `package`. The upstream release tag python-v0.7.5 is dated 2025-09-30 and matches the upload time. The PyPI owners of autogen-ext are AutoGenDevs and microsoft, the same as autogen-core and autogen-agentchat.
- Install hooks: the wheel is py3-none-any, so uv installs it and never builds the sdist. In the fresh sync, uv built only ziran itself. The wheel contains only `autogen_ext/` and dist-info: no `.pth` file, no entry_points.txt and no other top-level module.
- pip-audit, run the way CI does: `uv export --frozen --no-emit-project --all-extras` then `uvx pip-audit -r ... --no-deps --disable-pip` with CI's 7 `--ignore-vuln` ids. Result: "No known vulnerabilities found, 8 ignored". autogen-ext==0.7.5 is in the export with both hashes.
- Dependabot, `gh api repos/taoq-ai/ziran/dependabot/alerts?state=open`: 4 open alerts, minimatch (npm) and 3 chromadb GHSAs. The 3 chromadb ids are on CI's accepted-risk ignore list. There is no alert on autogen-*, openai, tiktoken or aiofiles.
- Runtime import path: grep finds `autogen_ext` only in examples/27-autogen-agent/agent.py:13 and in test stubs (tests/unit/test_autogen_adapter.py). In a fresh `uv sync --frozen --extra autogen --python 3.12` venv, importing ziran.application.factories, ziran.infrastructure.adapters.autogen_adapter and ziran.interfaces.cli.main loads 0 `autogen_ext` modules. `import autogen_ext.models.openai` succeeds (0.7.5).
- Example: with OPENAI_API_KEY unset, agent.py builds a RoundRobinGroupChat with members coder and reviewer. Its tools are stubs that run no model-written code. The key goes only to the default OpenAI client, the same as before this PR.
- Agent tooling did not change, so the scanner rule does not apply beyond the dependency audit above. No workflow, install script or pull_request_target change is in the diff.
- Mutants: not run. The diff changes no guard or validation.
- Confidence high: hashes, attestation publisher, owners and audit were each checked against PyPI and GitHub directly. A post-hoc compromise of the microsoft/autogen publisher would change this, and the hash pins mitigate it.
- Cleanup: scratch venv removed, no processes left running.

## Residual risk
autogen-ext is a large package (many optional integrations), but the extra pulls only its openai sub-extra, and ziran never imports it. Future 0.7.x updates inside `<0.8` arrive by relock and go through the same pip-audit gate.
