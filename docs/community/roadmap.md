# Roadmap

## Released

### v0.1 — Foundation

- :white_check_mark: Multi-Phase Trust Exploitation methodology (8 phases)
- :white_check_mark: NetworkX-based attack knowledge graph
- :white_check_mark: Attack library with YAML-defined vectors
- :white_check_mark: LangChain and CrewAI adapters
- :white_check_mark: Rich CLI with HTML/Markdown/JSON reports
- :white_check_mark: Tool chain analysis (30+ dangerous patterns)
- :white_check_mark: Skill CVE database (15 seed CVEs)

### v0.2 — Intelligence

- :white_check_mark: LLM-powered dynamic attack vector generation
- :white_check_mark: Static analysis engine (10 offline checks, SA001–SA010)
- :white_check_mark: PoC exploit generator (Python, cURL, Markdown)
- :white_check_mark: Policy engine with configurable rules
- :white_check_mark: CI/CD quality gate with SARIF output
- :white_check_mark: Amazon Bedrock adapter
- :white_check_mark: Expanded attack library (137 vectors across 9 files)
- :white_check_mark: OWASP LLM Top 10 mapping for all vectors

### v0.3 — Remote Scanning

- :white_check_mark: Remote agent scanning over HTTPS
- :white_check_mark: REST protocol handler (generic HTTP APIs)
- :white_check_mark: OpenAI-compatible protocol handler
- :white_check_mark: MCP (Model Context Protocol) handler
- :white_check_mark: A2A (Agent-to-Agent) protocol handler
- :white_check_mark: Auto-protocol detection
- :white_check_mark: Target YAML configuration with auth, TLS, retry
- :white_check_mark: GitHub Action (`taoq-ai/ziran@v0`)
- :white_check_mark: 11 dedicated A2A attack vectors
- :white_check_mark: 15 runnable examples

## Next: v0.4 — Hardening

- [ ] **Multi-agent coordination testing** — Test interactions between cooperating agents in supervisor/router architectures
- [ ] **Streaming support** — SSE/WebSocket streaming for long-running agent responses
- [ ] **Coverage for OWASP LLM04, LLM05, LLM10** — Model DoS, supply chain, and unbounded consumption vectors
- [ ] **Remediation engine** — Auto-generate fix suggestions and guardrail configurations
- [ ] **Adaptive campaigns** — Adjust attack strategy in real-time based on knowledge graph state

## Future

- [ ] **Cloud dashboard** — Centralized vulnerability management across agents
- [ ] **Community CVE portal** — Web-based CVE submission and search
- [ ] **IDE extension** — VS Code extension for inline security feedback
- [ ] **Agent benchmarking** — Comparative security scoring across agent versions
- [ ] **Compliance reports** — SOC 2, ISO 27001, and NIST AI RMF report templates

## How to Influence the Roadmap

- **Vote on issues** — :thumbsup: issues that matter to you
- **Open feature requests** — [Feature request template](https://github.com/taoq-ai/ziran/issues/new?template=feature_request.md)
- **Contribute code** — PRs for roadmap items are very welcome
- **Share feedback** — [Discussions](https://github.com/taoq-ai/ziran/discussions)
