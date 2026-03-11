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

### v0.6 — Pentesting Agent

- :white_check_mark: **Autonomous pentesting agent** — An LLM-powered agent that plans, executes, and adapts attack campaigns with minimal human intervention
- :white_check_mark: **Attack chain reasoning** — The agent reasons about discovered vulnerabilities to chain multi-step exploits
- :white_check_mark: **Interactive red-team mode** — Collaborate with the pentesting agent in a conversational interface
- :white_check_mark: **Finding deduplication** — Intelligent merging of related findings across automated and agent-driven scans

### v0.7 — Browser Scanning

- :white_check_mark: **Browser-based agent scanning** — Headless Playwright adapter for testing agents exposed via web chat UIs
- :white_check_mark: **Network interception** — Primary extraction via intercepted API calls (WebSocket, SSE, HTTP)
- :white_check_mark: **DOM fallback** — Secondary extraction from rendered page content when network interception is unavailable

### v0.8 — Depth & Ecosystem

- :white_check_mark: **Expanded tool chain patterns** — Grew from 32 to 102 dangerous patterns across 15 categories (cloud services, MCP, A2A, CI/CD, browser, crypto, and more) via YAML registry with custom pattern support
- :white_check_mark: **Encoding/obfuscation engine** — 8 encoding types (Base64, ROT13, leetspeak, homoglyph, hex, whitespace, mixed case, payload split) with composable pipelines via `--encoding` flag
- :white_check_mark: **Multi-turn jailbreak tactics** — Crescendo, context buildup, persona shift, and distraction tactics for progressive escalation within campaign phases
- :white_check_mark: **BOLA/BFLA authorization testing** — Authorization bypass detector and 20 attack vectors for Broken Object/Function Level Authorization testing
- :white_check_mark: **Promptfoo provider bridge** — Use ZIRAN as a custom Python provider for Promptfoo, enabling configuration-driven security testing with YAML test cases
- :white_check_mark: **OpenTelemetry tracing** — Opt-in distributed tracing for campaigns, phases, attacks, and detection with zero overhead when disabled

## v0.9 — Remediation Engine

- [ ] **Auto-generated fix suggestions** — Concrete code patches and guardrail configurations for discovered vulnerabilities
- [ ] **Guardrail templates** — Pre-built guardrail configurations for common agent frameworks
- [ ] **Remediation validation** — Re-scan after applying fixes to verify remediation effectiveness
- [ ] **Security policy generator** — Generate policy files from scan results

## v0.10 — MCP Server Mode

- [ ] **ZIRAN as an MCP server** — Expose scanning capabilities via the Model Context Protocol, enabling any MCP-compatible client to trigger scans
- [ ] **Tool-based scanning interface** — Scan agents, browse results, and manage campaigns through MCP tool calls
- [ ] **Integration with AI IDEs** — Use ZIRAN directly from Cursor, Windsurf, Claude Desktop, and other MCP clients
- [ ] **Continuous monitoring** — Long-running MCP server mode for periodic security assessments

## Future

- [ ] **Custom chain rule language** — User-defined tool chain patterns complementing ZIRAN's auto-discovery
- [ ] **Community chain patterns** — Crowdsourced dangerous tool chain submissions (like Skill CVEs but for tool compositions)
- [ ] **AgentSecBench** — Purpose-built benchmark: vulnerable agents with known tool chain vulnerabilities, demonstrating what ZIRAN catches that other tools miss
- [ ] **Tool chain methodology paper** — Publish the discovery-based approach as research
- [ ] **Community CVE portal** — Web-based CVE submission and search
- [ ] **Agent benchmarking** — Comparative security scoring across agent versions
- [ ] **Compliance reports** — SOC 2, ISO 27001, and NIST AI RMF report templates

## How to Influence the Roadmap

- **Vote on issues** — :thumbsup: issues that matter to you
- **Open feature requests** — [Feature request template](https://github.com/taoq-ai/ziran/issues/new?template=feature_request.md)
- **Contribute code** — PRs for roadmap items are very welcome
- **Share feedback** — [Discussions](https://github.com/taoq-ai/ziran/discussions)
