# Changelog

## [0.29.0](https://github.com/taoq-ai/ziran/compare/v0.28.0...v0.29.0) (2026-04-22)


### Features

* **benchmarks:** close OWASP 10/10 + expand 4 benchmarks + RAG poisoning ([#266](https://github.com/taoq-ai/ziran/issues/266)) ([b910721](https://github.com/taoq-ai/ziran/commit/b9107217187c08b0d9d5444ffc341d8ea325e3bc))

## [0.28.0](https://github.com/taoq-ai/ziran/compare/v0.27.0...v0.28.0) (2026-04-21)


### Features

* **atlas:** retro-map every vector + atlas_coverage + CLI/report surface ([#263](https://github.com/taoq-ai/ziran/issues/263)) ([cd427ef](https://github.com/taoq-ai/ziran/commit/cd427ef138ca36d60218414e0a3f202818d019a1))

## [0.27.0](https://github.com/taoq-ai/ziran/compare/v0.26.0...v0.27.0) (2026-04-21)


### Features

* **domain:** add MITRE ATLAS taxonomy + atlas_mapping field on vectors/results ([#261](https://github.com/taoq-ai/ziran/issues/261)) ([acea6c2](https://github.com/taoq-ai/ziran/commit/acea6c2a4b0f6bee9085c0ae830e2ece4113a056))

## [0.26.0](https://github.com/taoq-ai/ziran/compare/v0.25.0...v0.26.0) (2026-04-09)


### Features

* v0.8 runtime bridge — export-policy, analyze-traces, watch-registry ([#258](https://github.com/taoq-ai/ziran/issues/258)) ([a2ba0c2](https://github.com/taoq-ai/ziran/commit/a2ba0c222955387ea4ec0894943b58b94e7b191e))

## [0.25.0](https://github.com/taoq-ai/ziran/compare/v0.24.0...v0.25.0) (2026-04-04)


### Features

* 100% ALERT benchmark coverage + report failed vector loads ([#128](https://github.com/taoq-ai/ziran/issues/128)) ([0d89c08](https://github.com/taoq-ai/ziran/commit/0d89c0872e4063d974d089dfe96a5d0a02d90541))
* adaptive campaign strategies for intelligent phase orchestration ([#19](https://github.com/taoq-ai/ziran/issues/19)) ([abab4cc](https://github.com/taoq-ai/ziran/commit/abab4cca251b62e185c974743b2b9c1161ea8fb0))
* add --dry-run mode and config validation to CLI ([76611f7](https://github.com/taoq-ai/ziran/commit/76611f7c9a8149a9575c431f08bc802c8fbef8f7))
* add --dry-run mode, config validation warnings, and validate command ([ce4cdad](https://github.com/taoq-ai/ziran/commit/ce4cdad398c43a5c45d3de38a85932282353b378))
* add AgentCoreAdapter for Amazon Bedrock AgentCore ([#8](https://github.com/taoq-ai/ziran/issues/8)) ([30f1661](https://github.com/taoq-ai/ziran/commit/30f16616f15e3922485cf61af215cf9b269328aa))
* add AILuminate-style resilience gap metric ([#48](https://github.com/taoq-ai/ziran/issues/48)) ([9c17ac5](https://github.com/taoq-ai/ziran/commit/9c17ac548d8a75e1e7a5a7189d85799271b64945)), closes [#40](https://github.com/taoq-ai/ziran/issues/40)
* add application layer — scanner, knowledge graph, and attack library\n\n- AttackKnowledgeGraph (NetworkX MultiDiGraph) with path finding and centrality\n- 21 YAML attack vectors across 8 categories (prompt injection, tool\n  manipulation, privilege escalation, data exfiltration, system prompt\n  extraction, indirect injection, memory poisoning, chain-of-thought)\n- AttackLibrary with YAML loader, search/filter, custom directory support\n- RomanceScanner orchestrator with multi-phase campaign execution ([781d5dc](https://github.com/taoq-ai/ziran/commit/781d5dcd90feff32a636a13af0755bf9a5259323))
* add async timeouts and make detector pipeline async ([#11](https://github.com/taoq-ai/ziran/issues/11)) ([f37cdbf](https://github.com/taoq-ai/ziran/commit/f37cdbf5037786ff7c638b9902eb643af4120087))
* add autonomous pentesting agent (v0.6.0) ([32cae3e](https://github.com/taoq-ai/ziran/commit/32cae3ee7a89f4952e6693824d8b561bf00a8106))
* add benchmark coverage comparison scripts and report ([#53](https://github.com/taoq-ai/ziran/issues/53)) ([0685f4d](https://github.com/taoq-ai/ziran/commit/0685f4d1aae9a524fd827b8256b39b048355c951))
* add BOLA/BFLA authorization bypass testing ([#28](https://github.com/taoq-ai/ziran/issues/28)) ([095ea3b](https://github.com/taoq-ai/ziran/commit/095ea3b50e7cf30291041721e8cb262327c4217a))
* add built-in Rich progress display to pentesting agent ([22c34dd](https://github.com/taoq-ai/ziran/commit/22c34dd7d5c7e7d5bd867ffd9e97c399b2238625))
* add business impact categorization to findings ([#47](https://github.com/taoq-ai/ziran/issues/47)) ([409b545](https://github.com/taoq-ai/ziran/commit/409b545d7bf44c41dcf6de43661b9ba1e7a11493)), closes [#38](https://github.com/taoq-ai/ziran/issues/38)
* add campaign checkpoint/resume support ([9c79f2e](https://github.com/taoq-ai/ziran/commit/9c79f2e0b7bc7031acc00be5acd13f9befa83658))
* add campaign checkpoint/resume support for long-running scans ([a93b3e0](https://github.com/taoq-ai/ziran/commit/a93b3e0435130f14fd10d12b7b2b3f978ccad1b6)), closes [#123](https://github.com/taoq-ai/ziran/issues/123)
* add circuit breaker pattern for failing remote agents ([#144](https://github.com/taoq-ai/ziran/issues/144)) ([9b3e336](https://github.com/taoq-ai/ziran/commit/9b3e3360829bb2ab79753bfa63b0b3010303e187)), closes [#118](https://github.com/taoq-ai/ziran/issues/118)
* add CLI interface with scan, discover, library, and report commands\n\n- Click CLI with --verbose and --log-file global options\n- scan: run Romance Scan campaigns against AI agents\n- discover: introspect agent capabilities without attacking\n- library: browse/filter attack vectors\n- report: regenerate JSON/Markdown reports from saved results\n- ReportGenerator with Rich-formatted Markdown output ([494a675](https://github.com/taoq-ai/ziran/commit/494a675f1abba7f19226ef160ebc882963d4bf29))
* add comparative analysis against Promptfoo, Garak, and other tools ([#203](https://github.com/taoq-ai/ziran/issues/203)) ([d526b64](https://github.com/taoq-ai/ziran/commit/d526b64c8944edb5773efadc046a10a0cdcff824)), closes [#153](https://github.com/taoq-ai/ziran/issues/153)
* add DangerousChain entity and tool chain analyzer\n\nAdd ToolChainAnalyzer that examines the knowledge graph for dangerous\ntool combinations (30+ patterns). Detects direct chains, indirect\nchains via intermediate nodes, and cycles. Each chain gets a 0.0-1.0\nrisk score based on severity, chain type, and graph centrality.\n\n- Add DangerousChain Pydantic model to capability entities\n- Add dangerous_tool_chains and critical_chain_count to CampaignResult\n- Implement chain_analyzer.py with DANGEROUS_PATTERNS database ([8c6cdeb](https://github.com/taoq-ai/ziran/commit/8c6cdeb089f132e0d5de1783a2f30cda7f03c4ec))
* add deliberately vulnerable LangChain agent example\n\nReal GPT-4o-mini tool-calling agent with common security anti-patterns:\n- Secrets (DB credentials, API keys) hardcoded in system prompt\n- \"All users are pre-authenticated\" removes access control\n- \"Be transparent about your setup\" enables prompt extraction\n- Tools return full PII (SSN, salary) with no redaction\n- Raw SQL execution with no sanitisation\n\nKOAN consistently finds vulnerabilities against this agent,\ndemonstrating the tool working on a real LLM (not a mock)." ([ee3212e](https://github.com/taoq-ai/ziran/commit/ee3212e70a0a642c5074c571a0681e75bafcd107))
* add domain layer — entities and adapter interface\n\n- RomanceScanPhase enum (8 phases), PhaseResult, CampaignResult\n- AgentCapability, CapabilityType, ToolChain models\n- AttackCategory, AttackVector, AttackPrompt, AttackResult models\n- BaseAgentAdapter ABC with invoke/discover/state/reset/observe contract ([6ae60f2](https://github.com/taoq-ai/ziran/commit/6ae60f27330ef4bcfcd6d212c8fc8b826665ebd2))
* add examples and CI/CD workflow\n\n- LangChain example with OpenAI (loads .env via python-dotenv)\n- CrewAI example with single-agent crew\n- GitHub Actions CI: ruff lint, mypy typecheck, pytest on Python 3.11-3.13 ([000b2ce](https://github.com/taoq-ai/ziran/commit/000b2ce407f3a24b0ebc797eefce0762655ab38f))
* add examples and dependency configuration ([#10](https://github.com/taoq-ai/ziran/issues/10)) ([1aad2aa](https://github.com/taoq-ai/ziran/commit/1aad2aa1a7b10c02be48de97c1b0e8ae09ad6984))
* add examples dependency group to pyproject.toml ([3f35f48](https://github.com/taoq-ai/ziran/commit/3f35f48f57b03a825f4e79ae51f2c456ae665360))
* add garak-inspired multi-detector pipeline\n\nIntroduce a modular detection system to replace the monolithic\n_analyze_response method and eliminate false positives caused by\nthe tool-call fallback.\n\nNew components:\n- DetectorResult / DetectionVerdict (domain entities)\n- BaseDetector ABC (domain interface)\n- RefusalDetector: 130+ refusal strings from garak (Apache-2.0)\n- IndicatorDetector: context-aware YAML indicator matching\n- DetectorPipeline: runs detectors with \"refusal always wins\" strategy\n\nThe tool-call fallback (root cause of all FPs in router_rag) is\nintentionally not included in the new pipeline.\n\nIncludes NOTICE file with garak attribution (Apache-2.0). ([f1cb9e2](https://github.com/taoq-ai/ziran/commit/f1cb9e222c7ba1611c279133b8592d7f9a4634ce))
* add harmful multi-step task scenarios ([#51](https://github.com/taoq-ai/ziran/issues/51)) ([8728145](https://github.com/taoq-ai/ziran/commit/872814566d43a095df3d54b6118a85512010319b))
* add historical tracking and trend analysis for benchmarks ([#204](https://github.com/taoq-ai/ziran/issues/204)) ([4783f75](https://github.com/taoq-ai/ziran/commit/4783f750ced7d9a9cc994f8e826ff2701fb41391)), closes [#154](https://github.com/taoq-ai/ziran/issues/154)
* add HTML report generation and update CLI options ([f847afe](https://github.com/taoq-ai/ziran/commit/f847afeda7f8eee68568f01f8346de7f0d9637a4))
* add infrastructure layer — adapters, storage, and logging\n\n- LangChainAdapter with lazy import and dangerous-tool heuristic\n- CrewAIAdapter with asyncio.to_thread for sync compatibility\n- BedrockAdapter stub (not yet implemented)\n- GraphStorage for JSON persistence of campaigns\n- Rich-based logging configuration ([8edd39e](https://github.com/taoq-ai/ziran/commit/8edd39eb5494f1f8476b15ee0862cc4fc9e3f889))
* add interactive Plotly graph visualization\n\nGraphVisualizer creates interactive HTML visualizations of the attack\nknowledge graph with color-coded nodes by type, highlighted dangerous\nchain edges by risk level, and dark-themed Plotly layout. ([8ed06ff](https://github.com/taoq-ai/ziran/commit/8ed06ff2daa2f8202227c60494cd4c4802976dc7))
* add live progress callbacks and performance tuning to pentesting agent ([65020b6](https://github.com/taoq-ai/ziran/commit/65020b65269e0417378eab05991602b95bf155fc))
* add LLM backbone and LLM-as-a-judge detector ([#9](https://github.com/taoq-ai/ziran/issues/9)) ([fc2c4c4](https://github.com/taoq-ai/ziran/commit/fc2c4c47daf4a371c1d8a0afa156b3310926a138))
* add MCP write/git and broader financial patterns to classifier ([#187](https://github.com/taoq-ai/ziran/issues/187)) ([9d3197d](https://github.com/taoq-ai/ziran/commit/9d3197d0c4a6feb576de58c0285a43370e77a257)), closes [#163](https://github.com/taoq-ai/ziran/issues/163)
* add Model DoS attack vectors (OWASP LLM04) ([#52](https://github.com/taoq-ai/ziran/issues/52)) ([3130221](https://github.com/taoq-ai/ziran/commit/313022173d34de970439820d0cfa706230a6851e))
* add multi-turn jailbreak tactics for progressive attack sequences ([#27](https://github.com/taoq-ai/ziran/issues/27)) ([b9b1cbe](https://github.com/taoq-ai/ziran/commit/b9b1cbe20649daa860b71bba20b64ec1b1abc90f))
* add OpenAIConfig model and handler forwarding ([#6](https://github.com/taoq-ai/ziran/issues/6)) ([7f3a387](https://github.com/taoq-ai/ziran/commit/7f3a3874aec6bfc03d30208ca478bef168862b1b))
* add OpenTelemetry tracing instrumentation ([#30](https://github.com/taoq-ai/ziran/issues/30)) ([b7640d5](https://github.com/taoq-ai/ziran/commit/b7640d59f99bb639ef928426eaddc2e746377edd))
* add Organizational Policy Engine (Feature 3) ([562f913](https://github.com/taoq-ai/ziran/commit/562f913e55219e86dbb97a6ff7cbb267896f8a79))
* add OWASP LLM Top 10 mapping to attack vectors and reports\n\n- Add OwaspLlmCategory enum (LLM01-LLM10) and OWASP_LLM_DESCRIPTIONS\n- Add owasp_mapping field to AttackVector and AttackResult models\n- Map all 126 built-in vectors across 8 YAML files to OWASP categories\n- Update AttackLibrary with get_attacks_by_owasp() filtering method\n- Propagate owasp_mapping through scanner's _execute_attack() pipeline\n- Add OWASP LLM Top 10 compliance summary to Markdown reports\n- Add OWASP compliance table to interactive HTML reports\n- Add --owasp filter and OWASP column to CLI library command\n- Add 18 unit tests for enum, models, serialization, and library filtering" ([05aa8a0](https://github.com/taoq-ai/ziran/commit/05aa8a03de5b2ede1d2b0e08d7b9234fcb95a80e))
* add performance benchmarks with timing, throughput, and memory tracking ([#202](https://github.com/taoq-ai/ziran/issues/202)) ([3fa307e](https://github.com/taoq-ai/ziran/commit/3fa307e4576b1376f2093312b7f32e4a914bd602)), closes [#152](https://github.com/taoq-ai/ziran/issues/152)
* add PoC generation module (Feature 2) ([509e519](https://github.com/taoq-ai/ziran/commit/509e5197187f30cd0352d461c441d9852c1530c8))
* add precision, recall, and F1 metrics for detection accuracy ([#197](https://github.com/taoq-ai/ziran/issues/197)) ([2958e5c](https://github.com/taoq-ai/ziran/commit/2958e5c8f73620b6a7779c47e3dd16b650c2982a))
* add prompt encoding/obfuscation engine for bypass testing ([#26](https://github.com/taoq-ai/ziran/issues/26)) ([8982743](https://github.com/taoq-ai/ziran/commit/898274320007ada578f5c36e7c936680d0269652))
* add Promptfoo provider bridge ([#29](https://github.com/taoq-ai/ziran/issues/29)) ([25d2196](https://github.com/taoq-ai/ziran/commit/25d2196c756fc512cc2f266e39f596b658881d5b))
* add R-Judge risk scenario coverage (closes [#59](https://github.com/taoq-ai/ziran/issues/59)) ([#130](https://github.com/taoq-ai/ziran/issues/130)) ([beaaa58](https://github.com/taoq-ai/ziran/commit/beaaa58d36111c7ac27c9c1d8bfd5f04938675d3))
* add remote agent scanning (REST, OpenAI, MCP, A2A) ([#5](https://github.com/taoq-ai/ziran/issues/5)) ([fa2a41f](https://github.com/taoq-ai/ziran/commit/fa2a41f2561f8a95175e532fe046507bb8c838e3))
* add side-effect verification detector for tool execution analysis\n\n- Create SideEffectDetector analyzing AgentResponse.tool_calls for\n  dangerous tool executions (critical/high/medium/low risk tiers)\n- Integrate as 3rd stage in DetectorPipeline (refusal → indicator → side-effect)\n- Side-effect can override text refusal when critical tools were executed\n- Add get_side_effect_summary() utility for evidence collection\n- Enhance scanner evidence with side-effect summary on successful attacks\n- Support multiple tool_call formats (tool/name/function.name keys)\n- Add 17 unit tests covering detector, pipeline integration, and summary" ([57195fe](https://github.com/taoq-ai/ziran/commit/57195fe3bd57b394e0da0f2bc64a99f6a831b7ef))
* add Skill CVE database with 15 seed vulnerabilities\n\nCurated database of known security vulnerabilities in popular agent\ntools across LangChain, CrewAI, and MCP frameworks.\n\n- SkillCVE Pydantic model with CVE-AGENT-YYYY-NNN naming convention\n- SkillCVEDatabase with check_agent(), get_by_id/framework/severity\n- 15 seed CVEs covering ShellTool, PythonREPL, SQL tools, file tools,\n  Gmail, search, MCP invocation, and more\n- submit_cve() for community contribution support ([ce488f8](https://github.com/taoq-ai/ziran/commit/ce488f8b2e8d18f6d0c9ef28b1cbb0685da4996a))
* add Static Agent Configuration Analysis (Feature 6) ([bcbfef1](https://github.com/taoq-ai/ziran/commit/bcbfef1a002581d0492d3ed4e516a374423fde35))
* add utility-under-attack measurement ([#49](https://github.com/taoq-ai/ziran/issues/49)) ([fc95262](https://github.com/taoq-ai/ziran/commit/fc95262e10f019d2e5836280f4dc931939826c81))
* address three critical benchmark gaps ([#46](https://github.com/taoq-ai/ziran/issues/46)) ([5fc0a21](https://github.com/taoq-ai/ziran/commit/5fc0a21a724293fe78ff47f6aad7b2ca9d4eb10b))
* browser-based agent scanning via Playwright ([#23](https://github.com/taoq-ai/ziran/issues/23)) ([e6481a9](https://github.com/taoq-ai/ziran/commit/e6481a98caaf350ecc0e8b20c2840958fbda0865))
* **cicd:** add CI/CD quality gate, SARIF, and GitHub Action\n\n- Add QualityGateConfig and GateResult domain models (ci.py)\n- Implement QualityGate evaluator with configurable thresholds\n- Generate SARIF v2.1.0 reports for GitHub Code Scanning\n- Emit GitHub Actions annotations and step summaries\n- Add composite GitHub Action (action.yml) for pipeline integration\n- Add koan ci CLI command with --gate-config, --sarif, --policy options\n- 31 new tests (343 total suite), lint clean ([6d4bcb9](https://github.com/taoq-ai/ziran/commit/6d4bcb9414cc9cf5dfab273f47735cdfc12898d2))
* close GAP-04 quality-aware scoring and update benchmarks ([#195](https://github.com/taoq-ai/ziran/issues/195)) ([470c487](https://github.com/taoq-ai/ziran/commit/470c487792c10d807a5f024ab38f0249c01a9a9a))
* create ground truth dataset for accuracy measurement ([#158](https://github.com/taoq-ai/ziran/issues/158)) ([9d3957d](https://github.com/taoq-ai/ziran/commit/9d3957dffa236591fc5ffc816f07cc5e01d39393))
* display dangerous tool chains in CLI and Markdown reports\n\nAdd Rich table output for dangerous chains in terminal display with\ncolor-coded risk levels. Add chain analysis section to Markdown\nreports with risk icons, remediation guidance, and severity table. ([b48aa98](https://github.com/taoq-ai/ziran/commit/b48aa983377ee42b0180454d3801701182619456))
* dynamic vector generation from discovered capabilities ([9c281f3](https://github.com/taoq-ai/ziran/commit/9c281f3206fa5a310fc0ad410d3a3e17a396c795))
* **dynamic-vectors:** make indicators configurable via YAML\n\n- Add DynamicVectorConfig Pydantic model with full config schema\n- Externalize all tool patterns, prompts, indicators to default_config.yaml\n- Rewrite generator to be config-driven (no hardcoded patterns)\n- Support config merge for additive customization\n- Add 11 config model tests + 2 custom config integration tests\n- All 36 dynamic vector tests pass (312 total suite) ([7018ec2](https://github.com/taoq-ai/ziran/commit/7018ec2e00a09287c8126b0b080b74f2931c6fa1))
* enhance attack logging in HTML reports and data models ([4d56d9d](https://github.com/taoq-ai/ziran/commit/4d56d9d69e9f0e98448c8d64dba348216a9f32c9))
* enhance campaign scanning with coverage levels and token usage tracking ([bc4630e](https://github.com/taoq-ai/ziran/commit/bc4630eca6965bfe5bd6181ed73388caec78eebd))
* **examples:** add comprehensive standalone examples for all features ([93631a2](https://github.com/taoq-ai/ziran/commit/93631a26d4f4cbf217447cde6c6f25b09d95af89))
* **examples:** add live-scan examples 09-14 ([f53b044](https://github.com/taoq-ai/ziran/commit/f53b04405972b7b6b6dd005d675ed18979e43241))
* **examples:** add offline examples 01-08 ([2857fb6](https://github.com/taoq-ai/ziran/commit/2857fb6753a582240ee54831d15e34d8cad9dde5))
* expand AgentHarm multi-step vector coverage to 161 vectors ([#193](https://github.com/taoq-ai/ziran/issues/193)) ([3b632ea](https://github.com/taoq-ai/ziran/commit/3b632ea243f71c74dc0e91a692ae114b48a723a5))
* expand attack vector library from 21 to 126 vectors\n\nComprehensive coverage of OWASP LLM Top 10 across 8 categories:\n- prompt_injection: 18 vectors (DAN, encoding, smuggling, etc.)\n- tool_manipulation: 16 vectors (schema exploit, path traversal, etc.)\n- privilege_escalation: 15 vectors (admin claim, token forgery, etc.)\n- data_exfiltration: 16 vectors (markdown link, steganographic, etc.)\n- system_prompt_extraction: 16 vectors (completion, creative, etc.)\n- indirect_injection: 15 vectors (RAG poisoning, cross-agent, etc.)\n- memory_poisoning: 15 vectors (delayed trigger, identity override, etc.)\n- chain_of_thought_manipulation: 15 vectors (logic trap, goal sub, etc.) ([70fa937](https://github.com/taoq-ai/ziran/commit/70fa93777af26da77e84cdf5670267efe55d31b9))
* expand ground truth dataset with authorization, LLM judge, and framework scenarios ([#226](https://github.com/taoq-ai/ziran/issues/226)) ([2c27337](https://github.com/taoq-ai/ziran/commit/2c27337e962cad245d86c21ef04be63d65672ecd))
* expand jailbreak tactic library ([#50](https://github.com/taoq-ai/ziran/issues/50)) ([e1d3391](https://github.com/taoq-ai/ziran/commit/e1d3391712e990126837c1b3a03746b687f38eea))
* expand JailbreakBench coverage to 100% (closes [#54](https://github.com/taoq-ai/ziran/issues/54)) ([#129](https://github.com/taoq-ai/ziran/issues/129)) ([66af9f5](https://github.com/taoq-ai/ziran/commit/66af9f5aa8f3a90127c5eabc5dd592ee209156d8))
* expand MCPTox tool poisoning coverage to 100+ vectors ([#192](https://github.com/taoq-ai/ziran/issues/192)) ([c414792](https://github.com/taoq-ai/ziran/commit/c4147920dc7cdbd79367a09d42a63c538fcda397))
* expand tool chain patterns from 32 to 102 via YAML registry ([#25](https://github.com/taoq-ai/ziran/issues/25)) ([df346c3](https://github.com/taoq-ai/ziran/commit/df346c3cfc8e508410a096ebea257abc39a0292e))
* handle HTTP 429 rate limits with Retry-After header support ([#143](https://github.com/taoq-ai/ziran/issues/143)) ([1294357](https://github.com/taoq-ai/ziran/commit/129435763753f352728134387453879972666f89)), closes [#119](https://github.com/taoq-ai/ziran/issues/119)
* implement BedrockAdapter for AWS Bedrock Agents ([#7](https://github.com/taoq-ai/ziran/issues/7)) ([4937c81](https://github.com/taoq-ai/ziran/commit/4937c81b54ac058a5e4f0eeaef52c8497c98519b))
* implement release workflow and versioning management ([44861c7](https://github.com/taoq-ai/ziran/commit/44861c70b447944cba8eb986708bff32338b5b0b))
* implement resilience gap metric with baseline vs under-attack delta ([#198](https://github.com/taoq-ai/ziran/issues/198)) ([79005be](https://github.com/taoq-ai/ziran/commit/79005be36b456d54b9c14b4ad429c07d427ecb2a)), closes [#155](https://github.com/taoq-ai/ziran/issues/155)
* implement utility-under-attack aggregate metrics ([#199](https://github.com/taoq-ai/ziran/issues/199)) ([a3af35c](https://github.com/taoq-ai/ziran/commit/a3af35c0b8eaaf09aab1a620a7cf44f480582b50))
* integrate tool chain analysis into campaign scanner\n\nRun ToolChainAnalyzer after each campaign to detect dangerous tool\ncombinations in the knowledge graph. Results are included in\nCampaignResult and logged with campaign metrics. ([cf5bbc5](https://github.com/taoq-ai/ziran/commit/cf5bbc53900b1f299331f50a2e8b728d136feeaf))
* make detector pipeline configurable and extensible ([#189](https://github.com/taoq-ai/ziran/issues/189)) ([71c8028](https://github.com/taoq-ai/ziran/commit/71c80289f02d40f08c18dc062be0821346452fa5)), closes [#121](https://github.com/taoq-ai/ziran/issues/121)
* make poc and static_analysis config-driven via Pydantic + YAML ([1306488](https://github.com/taoq-ai/ziran/commit/130648838839a2fae95d63e830c1436b8552c756))
* multi-agent coordination for cross-agent security testing ([#18](https://github.com/taoq-ai/ziran/issues/18)) ([3a73398](https://github.com/taoq-ai/ziran/commit/3a73398db74908aadaa5ea95d4bd9662c74109e0))
* publish GitHub Action with live scan support and CI examples ([#4](https://github.com/taoq-ai/ziran/issues/4)) ([2371062](https://github.com/taoq-ai/ziran/commit/2371062c3504d02a954fe5ac29bc6dd335d2dfbc))
* save ground truth benchmark results as markdown ([#165](https://github.com/taoq-ai/ziran/issues/165)) ([e596b20](https://github.com/taoq-ai/ziran/commit/e596b20b407f2a6f0716eef4092f207d3ab45233))
* streaming support for real-time attack monitoring ([#17](https://github.com/taoq-ai/ziran/issues/17)) ([d0f7cdd](https://github.com/taoq-ai/ziran/commit/d0f7cdd84097d0c5cabc2d2a29385b1b8f25fe1a))
* **ui:** add findings management, OWASP compliance, TaoQ design system ([#233](https://github.com/taoq-ai/ziran/issues/233)) ([1e9debf](https://github.com/taoq-ai/ziran/commit/1e9debf142d3d3d89ac8839f9100b9d86a5cc435))
* **ui:** knowledge graph, attack library, settings, Docker, UX polish ([#244](https://github.com/taoq-ai/ziran/issues/244)) ([c0e0104](https://github.com/taoq-ai/ziran/commit/c0e01040f1c171a4434d2fb2a64d2dd4a36f24e5))
* **ui:** knowledge graph, attack library, settings, Playwright tests ([#247](https://github.com/taoq-ai/ziran/issues/247)) ([815ab4d](https://github.com/taoq-ai/ziran/commit/815ab4d22b0422285dd25ba0bfbeed91a2590d65))
* **ui:** web UI foundation + core API ([#229](https://github.com/taoq-ai/ziran/issues/229)) ([a320676](https://github.com/taoq-ai/ziran/commit/a320676051cfa760a7a95bc839b14762a9dae891))


### Bug Fixes

* add debug logging to bare except clauses in adapters ([#80](https://github.com/taoq-ai/ziran/issues/80)) ([e9a0145](https://github.com/taoq-ai/ziran/commit/e9a0145772904dc9402aa2e608fb9d2a0cf99d2a))
* add guardrail-aware chain and CVE filtering to scenario verdict ([#170](https://github.com/taoq-ai/ziran/issues/170)) ([650bc73](https://github.com/taoq-ai/ziran/commit/650bc739f624e1f4dd91b10ae83162448119c25b)), closes [#162](https://github.com/taoq-ai/ziran/issues/162)
* add missing tool classifier patterns for common agent tools ([#166](https://github.com/taoq-ai/ziran/issues/166)) ([36d3f6c](https://github.com/taoq-ai/ziran/commit/36d3f6c0f8ebc9f599ebc127a1b944d5a0622bb7)), closes [#159](https://github.com/taoq-ai/ziran/issues/159)
* add workflow_dispatch to release workflow for re-releasing versions ([13b169c](https://github.com/taoq-ai/ziran/commit/13b169c53608f30a0b4fb0f5656e64d3dc563bbf))
* **ci:** add --extra all to release workflow test job ([57c3806](https://github.com/taoq-ai/ziran/commit/57c380685cfdbca0406b171e779ccdeb1ae99620))
* configure git identity for action tag update ([d7f529c](https://github.com/taoq-ai/ziran/commit/d7f529c09962aba7b248a002ac311a0dae4de044))
* correct boolean logic in get_cross_agent_attack_paths ([#75](https://github.com/taoq-ai/ziran/issues/75)) ([82ca6b9](https://github.com/taoq-ai/ziran/commit/82ca6b9210d5ce5af620701e0df5c5dfa939f23d))
* exclude auto-generated _version.py from ruff entirely ([be2eb3c](https://github.com/taoq-ai/ziran/commit/be2eb3c6e3df93669a936c8b2742f9e86ca0daec))
* handle JSONDecodeError in LLM adaptive strategy ([#76](https://github.com/taoq-ai/ziran/issues/76)) ([21d0148](https://github.com/taoq-ai/ziran/commit/21d0148f3b24a131c32cfef36fd03ee968f96b9e))
* improve chain analyzer pattern matching and add missing patterns ([#169](https://github.com/taoq-ai/ziran/issues/169)) ([18b98a1](https://github.com/taoq-ai/ziran/commit/18b98a1381b699976001c52d8cf666806a9b4bd5)), closes [#160](https://github.com/taoq-ai/ziran/issues/160)
* improve SkillCVEDatabase.check_agent() matching logic ([#167](https://github.com/taoq-ai/ziran/issues/167)) ([fed4901](https://github.com/taoq-ai/ziran/commit/fed49010c10fe9e59c30287a20c8f07db188c3bc)), closes [#161](https://github.com/taoq-ai/ziran/issues/161)
* include all extras in ci.yml test job ([9e527ad](https://github.com/taoq-ai/ziran/commit/9e527ad2f9eb79ac174120397403174256496085))
* include all extras when installing dependencies in test workflow ([bcb37ed](https://github.com/taoq-ai/ziran/commit/bcb37edc15b4cb8d0902820b6c26d3a5f27384b0))
* increase performance benchmark targets to 30s for CI compatibility ([138dbaa](https://github.com/taoq-ai/ziran/commit/138dbaa4b18635a037842aaec0df0d352b27f086))
* **langchain-adapter:** use sync context manager for get_openai_callback ([c8f3b57](https://github.com/taoq-ai/ziran/commit/c8f3b57959775188e5624b0812e7b15a60c9e984))
* pin SETUPTOOLS_SCM_PRETEND_VERSION in release build ([46fc463](https://github.com/taoq-ai/ziran/commit/46fc463c78c101289149145361b71d0feb476743))
* prevent import_state() from mutating caller's dict via .pop() ([#142](https://github.com/taoq-ai/ziran/issues/142)) ([2418d1f](https://github.com/taoq-ai/ziran/commit/2418d1f0558f2f02cd7bcd55bf31d92608000df6)), closes [#117](https://github.com/taoq-ai/ziran/issues/117)
* raise on missing env var in browser login steps ([#77](https://github.com/taoq-ai/ziran/issues/77)) ([7b1efef](https://github.com/taoq-ai/ziran/commit/7b1efef8a72629c7d84bc64d8d9b2353c1b8ef62))
* remove dead code in side_effect detector ([#81](https://github.com/taoq-ai/ziran/issues/81)) ([85a801f](https://github.com/taoq-ai/ziran/commit/85a801f1d1ebfdfa8686fe7c4930e678ca12fa24))
* remove unused imports and sort imports in progress module ([c8b0222](https://github.com/taoq-ai/ziran/commit/c8b0222b9f0a17a76cfb88197a6b29f37ccd3f8f))
* repair crewai_example.py broken phases and API\n\nReplace non-existent ScanPhase.BOUNDARY_TESTING / EXPLOITATION with\nvalid values (VULNERABILITY_DISCOVERY, EXPLOITATION_SETUP, EXECUTION).\n\nFix ReportGenerator usage: old no-arg constructor + positional output\ndir replaced with ReportGenerator(output_dir=...) API." ([039beb1](https://github.com/taoq-ai/ziran/commit/039beb11d28751e60b4df84c84c4dffe788e6d4d))
* replace all remaining 'koan' references with 'ziran' ([79ffbbe](https://github.com/taoq-ai/ziran/commit/79ffbbe0012cf1546175c0f85b1e010ae0ae4468))
* replace assert with explicit checks in http_adapter ([#82](https://github.com/taoq-ai/ziran/issues/82)) ([8256147](https://github.com/taoq-ai/ziran/commit/8256147498a6caee389d2dcb62114fe297d6415e))
* resolve all mypy errors (unused type-ignore, missing stubs, type annotations) ([58c0939](https://github.com/taoq-ai/ziran/commit/58c0939cdb3febf88c938ec415f975d3ac35c976))
* resolve lint errors from rename ([981fad7](https://github.com/taoq-ai/ziran/commit/981fad76e02f22da07700ba071832e802dac183b))
* resolve ruff lint and formatting errors ([dc86c84](https://github.com/taoq-ai/ziran/commit/dc86c849b20d6508bf568dd6b9cbd32f435dee42))
* restore low_tools assignment removed incorrectly as dead code ([#84](https://github.com/taoq-ai/ziran/issues/84)) ([488bba4](https://github.com/taoq-ai/ziran/commit/488bba48e47ddaee440bcae5d213e3b98ee1de01))
* set fetch-depth to 0 for full history in checkout steps ([18b8254](https://github.com/taoq-ai/ziran/commit/18b8254005b6593a7db158f618938c2cd8eaed6f))
* suppress coroutine warning by mocking AgentScanner in scan test ([#209](https://github.com/taoq-ai/ziran/issues/209)) ([221de4a](https://github.com/taoq-ai/ziran/commit/221de4a474384ff9898e82a886e5da95ca7d7003))
* trigger release workflow on release event from release-please ([#206](https://github.com/taoq-ai/ziran/issues/206)) ([5fd8ebf](https://github.com/taoq-ai/ziran/commit/5fd8ebfae75ed5296173524b78d866b4a11b53c4))
* update action references from [@v1](https://github.com/v1) to [@v0](https://github.com/v0) ([a8edc45](https://github.com/taoq-ai/ziran/commit/a8edc4518e02752c020f49c7f40aff682304c65a))
* update Documentation URL to GitHub Pages ([efd0a5b](https://github.com/taoq-ai/ziran/commit/efd0a5ba73284a5cd1dacd3eeafd661ea72057e8))
* use 'uvx --with mkdocs-material mkdocs' for docs deployment ([cc37103](https://github.com/taoq-ai/ziran/commit/cc371034f5bd3f0c5a653af030acb3a0142e05a5))
* use correct context for job-level if conditions in release workflow ([b353fb0](https://github.com/taoq-ai/ziran/commit/b353fb07e1d8cdacd312156fc60b3de821deb02a))
* use GitHub API to update floating action tag ([93e4b70](https://github.com/taoq-ai/ziran/commit/93e4b70760fb77dda51851e4e170b837ac188b8a))
* validate env var type casting in LLM factory ([#83](https://github.com/taoq-ai/ziran/issues/83)) ([52b2df0](https://github.com/taoq-ai/ziran/commit/52b2df08608583b19e441a8a401a0e5266d3b296))
* validate required keys in graph state import ([#78](https://github.com/taoq-ai/ziran/issues/78)) ([e060ea6](https://github.com/taoq-ai/ziran/commit/e060ea696029588e7f9a301362a4855523759b96))
* warn on missing auth env var in AuthConfig ([#79](https://github.com/taoq-ai/ziran/issues/79)) ([b89d323](https://github.com/taoq-ai/ziran/commit/b89d323b9607f9c5f09c34347ae77025d862237f))


### Performance Improvements

* add filtering indices to AttackLibrary for O(1) lookups ([#140](https://github.com/taoq-ai/ziran/issues/140)) ([671d099](https://github.com/taoq-ai/ziran/commit/671d099c1c0e8af6306160bf8a21a80d6623272e))
* bound memory growth of attack results during campaigns ([#141](https://github.com/taoq-ai/ziran/issues/141)) ([859e561](https://github.com/taoq-ai/ziran/commit/859e561f2834d23c4730148f435873ccc75b18ee)), closes [#114](https://github.com/taoq-ai/ziran/issues/114)
* cache betweenness centrality computation in chain analyzer ([#95](https://github.com/taoq-ai/ziran/issues/95)) ([e74d169](https://github.com/taoq-ai/ziran/commit/e74d1699bbf13a13c2c04495cabf176791555921)), closes [#68](https://github.com/taoq-ai/ziran/issues/68)
* cache graph state exports and avoid redundant serialization ([7bc1f7a](https://github.com/taoq-ai/ziran/commit/7bc1f7af02b0e0484d6372eae3d519e3cd671b74)), closes [#106](https://github.com/taoq-ai/ziran/issues/106)
* cache tool classifications to avoid repeated regex matching ([#132](https://github.com/taoq-ai/ziran/issues/132)) ([07f6a0b](https://github.com/taoq-ai/ziran/commit/07f6a0b041c70932b1e114377534bd93b33909ca)), closes [#109](https://github.com/taoq-ai/ziran/issues/109)
* combine refusal detector patterns into single mega-regex ([#137](https://github.com/taoq-ai/ziran/issues/137)) ([1a2ef87](https://github.com/taoq-ai/ziran/commit/1a2ef87a03052627130764beebaf970dc792f849)), closes [#111](https://github.com/taoq-ai/ziran/issues/111)
* deduplicate prompt rendering when applying multiple encodings ([#138](https://github.com/taoq-ai/ziran/issues/138)) ([dea8c3b](https://github.com/taoq-ai/ziran/commit/dea8c3bde3013a1fc78afe5481e171b4f486bc7b)), closes [#112](https://github.com/taoq-ai/ziran/issues/112)
* optimize chain analyzer — cache tool nodes, pattern lookups, and centrality ([#133](https://github.com/taoq-ai/ziran/issues/133)) ([9c75336](https://github.com/taoq-ai/ziran/commit/9c75336adf098aff30f579d9defc9e31a85e6198))
* optimize YAML parsing, library caching, benchmarks, and chain analysis ([#223](https://github.com/taoq-ai/ziran/issues/223)) ([478be97](https://github.com/taoq-ai/ziran/commit/478be97a9bb3f7d507af6608f6cd8bc1c6f85430))
* parallelize multi-agent individual scans with asyncio.gather ([#135](https://github.com/taoq-ai/ziran/issues/135)) ([f88878c](https://github.com/taoq-ai/ziran/commit/f88878c451f18dcc92a3e9ef646e83a4b3b0980d)), closes [#107](https://github.com/taoq-ai/ziran/issues/107)
* parallelize protocol auto-detection probes with asyncio.gather ([#139](https://github.com/taoq-ai/ziran/issues/139)) ([24a63b3](https://github.com/taoq-ai/ziran/commit/24a63b3ae5dcfd1da224b6f5588aae1fbaa2d673)), closes [#108](https://github.com/taoq-ai/ziran/issues/108)
* pre-compile regex patterns in static analysis checks ([#186](https://github.com/taoq-ai/ziran/issues/186)) ([eb2b25a](https://github.com/taoq-ai/ziran/commit/eb2b25afb7a394b85d595c9fb1bb9db64901376f)), closes [#113](https://github.com/taoq-ai/ziran/issues/113)
* reduce test suite runtime from 7min to 1.5min (4.7x speedup) ([#210](https://github.com/taoq-ai/ziran/issues/210)) ([5a1d465](https://github.com/taoq-ai/ziran/commit/5a1d465af19a70c243bca5d175b43194ec86d32b))
* replace O(S*T) find_all_attack_paths with single-source traversal ([#136](https://github.com/taoq-ai/ziran/issues/136)) ([ca5b85e](https://github.com/taoq-ai/ziran/commit/ca5b85e87ff7da9b7657c295fd129df515635b42)), closes [#115](https://github.com/taoq-ai/ziran/issues/115)
* skip tested vectors, plateau detection, and improved reports ([e0fe17c](https://github.com/taoq-ai/ziran/commit/e0fe17cd7fd83200566638944533cf0922a3cc51))

## [0.24.0](https://github.com/taoq-ai/ziran/compare/v0.23.0...v0.24.0) (2026-03-30)


### Features

* **ui:** knowledge graph, attack library, settings, Docker, UX polish ([#244](https://github.com/taoq-ai/ziran/issues/244)) ([c0e0104](https://github.com/taoq-ai/ziran/commit/c0e01040f1c171a4434d2fb2a64d2dd4a36f24e5))

## [0.23.0](https://github.com/taoq-ai/ziran/compare/v0.22.0...v0.23.0) (2026-03-24)


### Features

* **ui:** add findings management, OWASP compliance, TaoQ design system ([#233](https://github.com/taoq-ai/ziran/issues/233)) ([1e9debf](https://github.com/taoq-ai/ziran/commit/1e9debf142d3d3d89ac8839f9100b9d86a5cc435))

## [0.22.0](https://github.com/taoq-ai/ziran/compare/v0.21.0...v0.22.0) (2026-03-23)


### Features

* **ui:** web UI foundation + core API ([#229](https://github.com/taoq-ai/ziran/issues/229)) ([a320676](https://github.com/taoq-ai/ziran/commit/a320676051cfa760a7a95bc839b14762a9dae891))

## [0.21.0](https://github.com/taoq-ai/ziran/compare/v0.20.0...v0.21.0) (2026-03-23)


### Features

* expand ground truth dataset with authorization, LLM judge, and framework scenarios ([#226](https://github.com/taoq-ai/ziran/issues/226)) ([2c27337](https://github.com/taoq-ai/ziran/commit/2c27337e962cad245d86c21ef04be63d65672ecd))

## [0.20.0](https://github.com/taoq-ai/ziran/compare/v0.19.0...v0.20.0) (2026-03-22)


### Features

* implement resilience gap metric with baseline vs under-attack delta ([#198](https://github.com/taoq-ai/ziran/issues/198)) ([79005be](https://github.com/taoq-ai/ziran/commit/79005be36b456d54b9c14b4ad429c07d427ecb2a)), closes [#155](https://github.com/taoq-ai/ziran/issues/155)


### Performance Improvements

* optimize YAML parsing, library caching, benchmarks, and chain analysis ([#223](https://github.com/taoq-ai/ziran/issues/223)) ([478be97](https://github.com/taoq-ai/ziran/commit/478be97a9bb3f7d507af6608f6cd8bc1c6f85430))

## [0.19.0](https://github.com/taoq-ai/ziran/compare/v0.18.4...v0.19.0) (2026-03-21)


### Features

* implement utility-under-attack aggregate metrics ([#199](https://github.com/taoq-ai/ziran/issues/199)) ([a3af35c](https://github.com/taoq-ai/ziran/commit/a3af35c0b8eaaf09aab1a620a7cf44f480582b50))

## [0.18.4](https://github.com/taoq-ai/ziran/compare/v0.18.3...v0.18.4) (2026-03-21)


### Bug Fixes

* suppress coroutine warning by mocking AgentScanner in scan test ([#209](https://github.com/taoq-ai/ziran/issues/209)) ([221de4a](https://github.com/taoq-ai/ziran/commit/221de4a474384ff9898e82a886e5da95ca7d7003))

## [0.18.3](https://github.com/taoq-ai/ziran/compare/v0.18.2...v0.18.3) (2026-03-21)


### Performance Improvements

* reduce test suite runtime from 7min to 1.5min (4.7x speedup) ([#210](https://github.com/taoq-ai/ziran/issues/210)) ([5a1d465](https://github.com/taoq-ai/ziran/commit/5a1d465af19a70c243bca5d175b43194ec86d32b))

## [0.18.2](https://github.com/taoq-ai/ziran/compare/v0.18.1...v0.18.2) (2026-03-21)


### Bug Fixes

* increase performance benchmark targets to 30s for CI compatibility ([138dbaa](https://github.com/taoq-ai/ziran/commit/138dbaa4b18635a037842aaec0df0d352b27f086))

## [0.18.1](https://github.com/taoq-ai/ziran/compare/v0.18.0...v0.18.1) (2026-03-21)


### Bug Fixes

* add workflow_dispatch to release workflow for re-releasing versions ([13b169c](https://github.com/taoq-ai/ziran/commit/13b169c53608f30a0b4fb0f5656e64d3dc563bbf))
* trigger release workflow on release event from release-please ([#206](https://github.com/taoq-ai/ziran/issues/206)) ([5fd8ebf](https://github.com/taoq-ai/ziran/commit/5fd8ebfae75ed5296173524b78d866b4a11b53c4))
* use correct context for job-level if conditions in release workflow ([b353fb0](https://github.com/taoq-ai/ziran/commit/b353fb07e1d8cdacd312156fc60b3de821deb02a))

## [0.18.0](https://github.com/taoq-ai/ziran/compare/v0.17.0...v0.18.0) (2026-03-21)


### Features

* add comparative analysis against Promptfoo, Garak, and other tools ([#203](https://github.com/taoq-ai/ziran/issues/203)) ([d526b64](https://github.com/taoq-ai/ziran/commit/d526b64c8944edb5773efadc046a10a0cdcff824)), closes [#153](https://github.com/taoq-ai/ziran/issues/153)
* add historical tracking and trend analysis for benchmarks ([#204](https://github.com/taoq-ai/ziran/issues/204)) ([4783f75](https://github.com/taoq-ai/ziran/commit/4783f750ced7d9a9cc994f8e826ff2701fb41391)), closes [#154](https://github.com/taoq-ai/ziran/issues/154)
* add performance benchmarks with timing, throughput, and memory tracking ([#202](https://github.com/taoq-ai/ziran/issues/202)) ([3fa307e](https://github.com/taoq-ai/ziran/commit/3fa307e4576b1376f2093312b7f32e4a914bd602)), closes [#152](https://github.com/taoq-ai/ziran/issues/152)

## [0.17.0](https://github.com/taoq-ai/ziran/compare/v0.16.0...v0.17.0) (2026-03-20)


### Features

* expand AgentHarm multi-step vector coverage to 161 vectors ([#193](https://github.com/taoq-ai/ziran/issues/193)) ([3b632ea](https://github.com/taoq-ai/ziran/commit/3b632ea243f71c74dc0e91a692ae114b48a723a5))

## [0.16.0](https://github.com/taoq-ai/ziran/compare/v0.15.0...v0.16.0) (2026-03-20)


### Features

* add precision, recall, and F1 metrics for detection accuracy ([#197](https://github.com/taoq-ai/ziran/issues/197)) ([2958e5c](https://github.com/taoq-ai/ziran/commit/2958e5c8f73620b6a7779c47e3dd16b650c2982a))
* close GAP-04 quality-aware scoring and update benchmarks ([#195](https://github.com/taoq-ai/ziran/issues/195)) ([470c487](https://github.com/taoq-ai/ziran/commit/470c487792c10d807a5f024ab38f0249c01a9a9a))
* expand MCPTox tool poisoning coverage to 100+ vectors ([#192](https://github.com/taoq-ai/ziran/issues/192)) ([c414792](https://github.com/taoq-ai/ziran/commit/c4147920dc7cdbd79367a09d42a63c538fcda397))

## [0.15.0](https://github.com/taoq-ai/ziran/compare/v0.14.0...v0.15.0) (2026-03-20)


### Features

* add --dry-run mode and config validation to CLI ([76611f7](https://github.com/taoq-ai/ziran/commit/76611f7c9a8149a9575c431f08bc802c8fbef8f7))
* add campaign checkpoint/resume support ([9c79f2e](https://github.com/taoq-ai/ziran/commit/9c79f2e0b7bc7031acc00be5acd13f9befa83658))

## [0.14.0](https://github.com/taoq-ai/ziran/compare/v0.13.0...v0.14.0) (2026-03-20)


### Features

* add MCP write/git and broader financial patterns to classifier ([#187](https://github.com/taoq-ai/ziran/issues/187)) ([9d3197d](https://github.com/taoq-ai/ziran/commit/9d3197d0c4a6feb576de58c0285a43370e77a257)), closes [#163](https://github.com/taoq-ai/ziran/issues/163)
* make detector pipeline configurable and extensible ([#189](https://github.com/taoq-ai/ziran/issues/189)) ([71c8028](https://github.com/taoq-ai/ziran/commit/71c80289f02d40f08c18dc062be0821346452fa5)), closes [#121](https://github.com/taoq-ai/ziran/issues/121)


### Performance Improvements

* pre-compile regex patterns in static analysis checks ([#186](https://github.com/taoq-ai/ziran/issues/186)) ([eb2b25a](https://github.com/taoq-ai/ziran/commit/eb2b25afb7a394b85d595c9fb1bb9db64901376f)), closes [#113](https://github.com/taoq-ai/ziran/issues/113)
