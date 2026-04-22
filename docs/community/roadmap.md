# Roadmap

Priorities shift as the landscape changes. This page tracks **themes** we're actively investing in — not fixed version schedules. For what's currently in flight, see the [active milestones on GitHub](https://github.com/taoq-ai/ziran/milestones). For commercial / hosted-platform work, see the [ZIRAN Cloud planning notes](#ziran-cloud).

---

## Recently Delivered

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
- :white_check_mark: Expanded attack library with OWASP LLM Top 10 mapping

### v0.3 — Remote Scanning

- :white_check_mark: Remote agent scanning over HTTPS (REST, OpenAI, MCP, A2A handlers with auto-detection)
- :white_check_mark: Target YAML configuration with auth, TLS, retry
- :white_check_mark: GitHub Action (`taoq-ai/ziran@v0`)

### v0.4 — Multi-Vendor & LLM Backbone

- :white_check_mark: Multi-vendor LLM support via LiteLLM (OpenAI, Anthropic, AWS Bedrock, Google, and more)
- :white_check_mark: LLM-as-a-Judge detection for nuanced semantic analysis
- :white_check_mark: Amazon Bedrock Agent and AgentCore adapters

### v0.5 — Adaptive Intelligence

- :white_check_mark: Streaming support (SSE, WebSocket)
- :white_check_mark: Multi-agent coordination — topology discovery, cross-agent scanning
- :white_check_mark: Adaptive campaign strategies — fixed, rule-based, and LLM-driven phase orchestration
- :white_check_mark: 327 multi-agent attack vectors covering cross-agent injection, delegation-chain manipulation, shared-memory poisoning

### v0.6 — Autonomous Pentesting Agent

- :white_check_mark: LangGraph-based pentesting agent (planner, executor, reasoner, reporter)
- :white_check_mark: Attack-chain reasoning across multi-step exploits
- :white_check_mark: Interactive red-team mode
- :white_check_mark: Finding deduplication across automated and agent-driven scans

### v0.7 — Browser Scanning

- :white_check_mark: Headless Playwright adapter for agents behind web chat UIs
- :white_check_mark: Network interception + DOM-fallback extraction

### v0.8 — Runtime Bridge

- :white_check_mark: Policy export — OPA/Rego, Cedar, NeMo Colang, Invariant Labs DSL bundles
- :white_check_mark: Trace analysis — ingest OTel / Langfuse production traces, match against dangerous chains
- :white_check_mark: MCP registry watcher — poll manifests, detect drift, flag typosquats
- :white_check_mark: CI/CD templates for GitHub, GitLab, Jenkins, CircleCI, Azure Pipelines

### v0.13 — Benchmark Maturity

- :white_check_mark: **100% OWASP LLM Top 10 coverage** (10/10 categories, all strong+)
- :white_check_mark: **MITRE ATLAS mapping** on every vector (72/86 techniques, 14/14 agent-specific)
- :white_check_mark: Defence profile schema + evasion-rate metric
- :white_check_mark: RAG-poisoning attack category
- :white_check_mark: Benchmark expansion against TensorTrust, WildJailbreak, ToolEmu, CyberSecEval

See the [benchmark coverage comparison](../reference/benchmarks/coverage-comparison.md) for the full dashboard.

---

## In Flight & Next Up

Work is organised into **themes**, each tracked by an open GitHub milestone. Version numbers aren't published here because priorities shift as the landscape does — the themes are the stable commitment.

### Theme: Runtime Loop

Close the **pre-deploy → runtime → observability** loop that v0.8 sketched. Today the runtime-bridge commands (`export-policy`, `analyze-traces`, `watch-registry`) ship infrastructure but leave the integration endpoints to humans. This theme wires them through to real systems.

- [ ] **NeMo Guardrails evaluator adapter** — makes `evasion_rate` computable for the first concrete guardrail; unblocks Lakera and Invariant follow-ups ([#271](https://github.com/taoq-ai/ziran/issues/271))
- [ ] **Registry-watcher alerting** — Slack + GitHub issue output adapters when MCP drift is detected ([#272](https://github.com/taoq-ai/ziran/issues/272))
- [ ] **Policy auto-refresh GitHub Action** — PR-based refresh of exported policies when the library or target config changes ([#273](https://github.com/taoq-ai/ziran/issues/273))
- [ ] **Trace-analysis → GitHub issues** — auto-file issues when production traces match dangerous chains ([#274](https://github.com/taoq-ai/ziran/issues/274))

### Theme: Detection Depth

Close frontier attack gaps (gradient-based attacks, many-shot jailbreaks, tool-schema confusion) and detection-quality gaps (multilingual refusal, untuned thresholds, no precision/recall baseline). Benchmark what ZIRAN claims against labelled ground truth.

- [ ] **Gradient-based adversarial attacks (GCG / PAIR)** — new `AdvancedAttackGenerator` subsystem for optimiser-based attacks ([#275](https://github.com/taoq-ai/ziran/issues/275))
- [ ] **Many-shot jailbreaking category** — exploits long-context windows with hundreds of shots ([#276](https://github.com/taoq-ai/ziran/issues/276))
- [ ] **Tool-schema confusion category** — malformed schemas, parameter type confusion, enum injection ([#277](https://github.com/taoq-ai/ziran/issues/277))
- [ ] **Multilingual refusal detection** — extend the refusal detector beyond English (Chinese, Spanish, German, French, Japanese) ([#278](https://github.com/taoq-ai/ziran/issues/278))
- [ ] **Precision/recall/F1 benchmark per detector** — labelled ground-truth eval, threshold tuning methodology ([#279](https://github.com/taoq-ai/ziran/issues/279))
- [ ] **Pentesting-agent ground-truth evaluation** — does the autonomous agent find vulnerabilities the rule-based scanner misses? ([#280](https://github.com/taoq-ai/ziran/issues/280))

### Theme: Production Scale

Harden the runtime for enterprise production use — rate-limiting, structured logging, resumable checkpoints, proper metrics.

- [ ] **Rate-limiting + retry with backoff** — per-provider token bucket, exponential retry on 429s, scale beyond the current 5-concurrent default ([#281](https://github.com/taoq-ai/ziran/issues/281))
- [ ] **Structured JSON logging (structlog)** — machine-queryable audit trail for ELK / Datadog / Splunk ingestion ([#282](https://github.com/taoq-ai/ziran/issues/282))
- [ ] **Partial-phase checkpoint resume** — save progress within a phase; don't lose 30 min of work on a crash ([#283](https://github.com/taoq-ai/ziran/issues/283))
- [ ] **OTel metrics export (Prometheus-compatible)** — counters, gauges, histograms beyond the existing span export ([#284](https://github.com/taoq-ai/ziran/issues/284))

### Theme: Ecosystem + Enterprise

Expand framework reach and unlock enterprise-facing positioning: incremental scanning for dev-loop speed, compliance evidence bundles for procurement.

- [ ] **AutoGen adapter** — Microsoft's multi-agent framework ([#285](https://github.com/taoq-ai/ziran/issues/285))
- [ ] **Anthropic SDK native adapter** — direct path, no LangChain wrapping ([#286](https://github.com/taoq-ai/ziran/issues/286))
- [ ] **Langfuse API trace ingestor** — live pulls, not file exports ([#287](https://github.com/taoq-ai/ziran/issues/287))
- [ ] **Incremental / diff scanning** — only re-test changed vectors; unlock pre-commit-hook and fast-CI-gate use ([#288](https://github.com/taoq-ai/ziran/issues/288))
- [ ] **Compliance evidence bundles** — EU AI Act / NIST AI RMF / ISO 42001 mapping + export ([#289](https://github.com/taoq-ai/ziran/issues/289))

### Opportunistic — Not in a theme

These don't block a milestone but are worth landing when someone has a slot:

- [ ] **Attack library community submission workflow** — clear contributor path, PR template, CI schema linter ([#290](https://github.com/taoq-ai/ziran/issues/290)) — `good first issue`
- [ ] **Supply-chain signing** — cosign signatures on releases, CycloneDX SBOM, SLSA provenance ([#291](https://github.com/taoq-ai/ziran/issues/291))
- [ ] **`ziran init` scaffolding command** — one-liner onboarding ([#292](https://github.com/taoq-ai/ziran/issues/292)) — `good first issue`
- [ ] **Expand ATLAS coverage to remaining tactics** — AI Model Access, AI Attack Staging ([#264](https://github.com/taoq-ai/ziran/issues/264))
- [ ] **asqav signing integration sketch** — downstream signing of ZIRAN outputs ([#259](https://github.com/taoq-ai/ziran/issues/259))
- [ ] **HTML report graph pagination** — perf improvement for large campaigns ([#217](https://github.com/taoq-ai/ziran/issues/217))

### UI Hardening

Tracked as a parallel stream. See [UI-labelled issues](https://github.com/taoq-ai/ziran/labels/ui).

---

## Longer Term

Directions we're watching but not yet committed to a milestone on. These are the places where the shape of the work isn't settled yet — what ships depends on signal from users and on what the surrounding ecosystem does.

- **Multimodal prompt injection** — image / document / audio attack surface, once multimodal agents are common production targets
- **Custom chain rule language** — user-defined tool chain patterns complementing auto-discovery
- **AgentSecBench** — purpose-built benchmark of deliberately-vulnerable agents with known tool-chain vulnerabilities; demonstrates what ZIRAN catches that other tools miss
- **Tool chain methodology paper** — publish the discovery-based approach as research
- **Red-team / blue-team split mode** — meaningful once the DefenceProfile evaluator ecosystem has multiple implementations (waits for #271 and the next evaluator)
- **Federated agent trust boundary modelling** — cross-org / cross-network agent topologies

---

## ZIRAN Cloud

A hosted platform layer is planned for commercial / enterprise use cases. OSS ZIRAN remains the foundation — Cloud builds on top rather than replacing anything. Current direction is tracked privately but the capabilities under consideration include:

- **Managed parallel scanning** — campaigns fan out across worker pools with global rate-limiting; no self-hosted Ray/Celery required
- **Curated premium threat-intel feed** — continuously updated vector library with researcher provenance, SLA-backed, complementing the open community-submission path
- **Multi-tenant RBAC** — red-team / blue-team role dashboards, audit logs, team-based compliance workflows

These are deliberately not in the OSS roadmap because they either require hosted infrastructure to be useful or would conflict with the partner ecosystem (NeMo, Lakera, Invariant, Langfuse) that OSS ZIRAN works **with**, not against.

---

## How to Influence the Roadmap

- **Vote on issues** — :thumbsup: issues that matter to you; we read the vote counts when prioritising
- **Open feature requests** — [feature request template](https://github.com/taoq-ai/ziran/issues/new?template=feature_request.md)
- **Contribute code** — PRs for any of the themed issues above are very welcome; look for `good first issue` labels
- **Share feedback** — [Discussions](https://github.com/taoq-ai/ziran/discussions)
