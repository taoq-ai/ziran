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

### v0.4 — Multi-Vendor & LLM Backbone

- :white_check_mark: Multi-vendor LLM support via LiteLLM (OpenAI, Anthropic, AWS Bedrock, Google, and more)
- :white_check_mark: LLM-as-a-Judge detection for nuanced semantic analysis
- :white_check_mark: Amazon Bedrock Agent and AgentCore adapters
- :white_check_mark: Dependency capping and compatibility hardening

### v0.5 — Adaptive Intelligence

- :white_check_mark: **Streaming support** — SSE and WebSocket protocol handlers for real-time attack monitoring
- :white_check_mark: **Multi-agent coordination** — Topology discovery, individual and cross-agent scanning for supervisor, router, peer-to-peer, hierarchical, and pipeline architectures
- :white_check_mark: **Adaptive campaigns** — Three execution strategies: fixed (sequential), adaptive (rule-based), and LLM-adaptive (LLM-driven phase orchestration)
- :white_check_mark: **Campaign strategy protocol** — Extensible interface for custom campaign strategies
- :white_check_mark: **327 multi-agent attack vectors** — Cross-agent prompt injection, delegation chain manipulation, shared memory poisoning
- :white_check_mark: **18 runnable examples** — Including multi-agent, streaming, and adaptive campaign demos

## Next: v0.6 — Pentesting Agent

The flagship feature — an autonomous AI agent that performs penetration testing:

- [ ] **Autonomous pentesting agent** — An LLM-powered agent that plans, executes, and adapts attack campaigns with minimal human intervention
- [ ] **Attack chain reasoning** — The agent reasons about discovered vulnerabilities to chain multi-step exploits
- [ ] **Interactive red-team mode** — Collaborate with the pentesting agent in a conversational interface
- [ ] **Finding deduplication** — Intelligent merging of related findings across automated and agent-driven scans

## v0.7 — Remediation Engine

- [ ] **Auto-generated fix suggestions** — Concrete code patches and guardrail configurations for discovered vulnerabilities
- [ ] **Guardrail templates** — Pre-built guardrail configurations for common agent frameworks
- [ ] **Remediation validation** — Re-scan after applying fixes to verify remediation effectiveness
- [ ] **Security policy generator** — Generate policy files from scan results

## v0.8 — MCP Server Mode

- [ ] **ZIRAN as an MCP server** — Expose scanning capabilities via the Model Context Protocol, enabling any MCP-compatible client to trigger scans
- [ ] **Tool-based scanning interface** — Scan agents, browse results, and manage campaigns through MCP tool calls
- [ ] **Integration with AI IDEs** — Use ZIRAN directly from Cursor, Windsurf, Claude Desktop, and other MCP clients
- [ ] **Continuous monitoring** — Long-running MCP server mode for periodic security assessments

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
