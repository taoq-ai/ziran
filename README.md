# ZIRAN

[![CI](https://github.com/taoq-ai/ziran/actions/workflows/ci.yml/badge.svg)](https://github.com/taoq-ai/ziran/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ziran.svg)](https://pypi.org/project/ziran/)
[![License](https://img.shields.io/badge/License-FSL--1.1--ALv2-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

ZIRAN tests AI agents for vulnerabilities that appear when their tools combine. It maps each tool
an agent can call to a capability, puts the capabilities in a graph and walks it for dangerous
chains, such as a file read that can feed an outbound HTTP request. Against a live agent it then
attacks those chains and checks what the tools did, as well as what the agent replied. It reads
Claude Code agents and plugins, LangChain, CrewAI, MCP and A2A agents, and any agent served over
HTTPS.

## Install

```bash
pip install ziran
pip install "ziran[langchain]"   # or crewai, a2a, streaming, pentest, otel, all
```

## Quick start

```bash
ziran audit ./agents/                                       # static audit, no LLM or API key
ziran scan --framework langchain --agent-path my_agent.py   # in-process campaign
ziran scan --target target.yaml                             # remote agent over HTTPS
```

Each scan writes HTML, Markdown and JSON reports to `reports/`.
[Getting Started](https://taoq-ai.github.io/ziran/getting-started/) shows the target file, the
Python API and Docker.

## Example

A Claude Code subagent declares `tools: Read, WebFetch`. Neither tool looks wrong on its own.
Audit it with [examples/24-claude-code-agent-audit/](examples/24-claude-code-agent-audit/):

```console
$ ziran audit agents/
...
┏━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check  ┃ Severity   ┃ Message                                                               ┃ Location               ┃
┡━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ SA003  │ high       │ Agent 'researcher' is granted dangerous tool 'WebFetch'               │ agents/researcher.md:4 │
├────────┼────────────┼───────────────────────────────────────────────────────────────────────┼────────────────────────┤
│ CC001  │ critical   │ Agent 'researcher': data_exfiltration via Read -> WebFetch            │ agents/researcher.md:4 │
├────────┼────────────┼───────────────────────────────────────────────────────────────────────┼────────────────────────┤
│ LT001  │ critical   │ Agent 'researcher': lethal_trifecta: private data from Read;          │ agents/researcher.md:4 │
│        │            │ untrusted content from WebFetch; egress via WebFetch                  │                        │
└────────┴────────────┴───────────────────────────────────────────────────────────────────────┴────────────────────────┘
...
FAILED — critical issues found
```

`Read -> WebFetch` is a data exfiltration path: a prompt injection in any file the agent reads
can tell it to send that file to a URL the attacker picks. A per-tool check passes this agent.

## What it finds

- Dangerous tool chains: 30+ patterns, such as `read_file -> http_request`.
- The lethal trifecta: private data, untrusted content and egress in one agent.
- Side effects: a tool call fired while the reply says "I can't do that".
- Trust between agents: peer messages accepted without validation in multi-agent systems.
- Attack coverage: 694 vectors, 10/10 OWASP LLM Top 10 categories and 85/100 MITRE ATLAS
  techniques.

## Documentation

The [docs site](https://taoq-ai.github.io/ziran/) covers:

- [framework adapters](https://taoq-ai.github.io/ziran/guides/adapters/) and
  [remote agents](https://taoq-ai.github.io/ziran/guides/remote-agents/);
- [how it works](https://taoq-ai.github.io/ziran/#how-it-works) and
  [how it compares](https://taoq-ai.github.io/ziran/#how-it-compares);
- [benchmarks and coverage](https://taoq-ai.github.io/ziran/reference/benchmarks/coverage-comparison/);
- [the CI gate](https://taoq-ai.github.io/ziran/guides/ci-integrations/) (GitHub Action, SARIF);
- [Claude Code plugins](https://taoq-ai.github.io/ziran/guides/claude-code/) and the
  [ZIRAN plugin for Claude Code](https://taoq-ai.github.io/ziran/guides/claude-code/#claude-code-plugin-for-ziran);
- the [CLI reference](https://taoq-ai.github.io/ziran/reference/cli/) and
  [contributing](https://taoq-ai.github.io/ziran/community/contributing/).

Runnable examples live in [examples/](examples/).

## License

ZIRAN is source-available, not open source. New versions are released under the
[Functional Source License 1.1, Apache-2.0 future licence](LICENSE) (`FSL-1.1-ALv2`): you may use,
modify and redistribute it for any purpose except a competing commercial product or service, and
each version becomes Apache-2.0 two years after its release.

Versions up to and including v0.42.0, and the `study-v1` and `study-v2` tags, were released under
Apache-2.0 and stay under it. See [NOTICE](NOTICE) for the details and for third-party
attributions.

Commercial licences are available from TaoQ AI at [info@taoq.ai](mailto:info@taoq.ai), on the
[standard terms](COMMERCIAL-LICENSE.md) and an [order form](COMMERCIAL-ORDER-FORM.md).
