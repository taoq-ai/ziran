# ZIRAN Benchmark Coverage

How ZIRAN's attack vector library compares against published AI agent security benchmarks.

## Current State

| Metric | Value |
|--------|-------|
| Attack vectors | **639** |
| Attack categories | **11** |
| OWASP LLM Top 10 | **100.0%** (10/10) |
| Multi-turn tactics | **10** |
| Encoding types | **12** |
| Benchmarks analyzed | **20** |
| MITRE ATLAS techniques covered | **72/86** (14/14 agent-specific) |
| Gap closure | **39.1%** (9/23) |

## OWASP LLM Top 10 Coverage

| Code | Category | Vectors | Status |
|------|----------|---------|--------|
| **LLM01** | Prompt Injection | 468 | :white_check_mark: Comprehensive |
| **LLM02** | Insecure Output Handling | 201 | :white_check_mark: Comprehensive |
| **LLM03** | Training Data Poisoning | 19 | :white_check_mark: Strong |
| **LLM04** | Model Denial of Service | 14 | :white_check_mark: Strong |
| **LLM05** | Supply Chain Vulnerabilities | 18 | :white_check_mark: Strong |
| **LLM06** | Sensitive Information Disclosure | 110 | :white_check_mark: Comprehensive |
| **LLM07** | Insecure Plugin Design | 145 | :white_check_mark: Comprehensive |
| **LLM08** | Excessive Agency | 151 | :white_check_mark: Comprehensive |
| **LLM09** | Overreliance | 15 | :white_check_mark: Strong |
| **LLM10** | Unbounded Consumption | 10 | :white_check_mark: Strong |

## Benchmark Comparison

| Benchmark | Venue | Dimension | Target | ZIRAN | Progress | Status | Gap |
|-----------|-------|-----------|-------:|------:|----------|--------|-----|
| **AgentHarm** | ICLR 2025 | Harm categories | 11 | 11 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-06](https://github.com/taoq-ai/ziran/issues/37) |
| **AgentHarm** | ICLR 2025 | Multi-step vectors | 440 | 161 | `█████░░░░░░░░░░` 36.6% | :construction: open | [GAP-23](https://github.com/taoq-ai/ziran/issues/131) |
| **InjecAgent** | ACL 2024 | Indirect injection vectors | 1,054 | 63 | `█░░░░░░░░░░░░░░` 6.0% | :construction: open | [GAP-02](https://github.com/taoq-ai/ziran/issues/33) |
| **AgentDojo** | NeurIPS 2024 | Indirect injection vectors | 629 | 63 | `██░░░░░░░░░░░░░` 10.0% | :construction: open | [GAP-02](https://github.com/taoq-ai/ziran/issues/33) |
|  |  | Utility measurement (baseline + post-attack) | 1 | 1 | `███████████████` 100.0% |  |  |
| **HarmBench** | ICML 2024 | Attack tactics | 18 | 10 | `████████░░░░░░░` 55.6% | :white_check_mark: closed | [GAP-08](https://github.com/taoq-ai/ziran/issues/39) |
|  |  | Jailbreak vectors | 510 | 206 | `██████░░░░░░░░░` 40.4% |  |  |
| **JailbreakBench** | NeurIPS 2024 | JBB categories (10) | 10 | 10 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-15](https://github.com/taoq-ai/ziran/issues/54) |
|  |  | Prompt injection vectors | 100 | 206 | `███████████████` 100% |  |  |
| **StrongREJECT** | 2024 | StrongREJECT composite formula | 1 | 1 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-04](https://github.com/taoq-ai/ziran/issues/35) |
|  |  | Scoring dimensions (refusal, specificity, convincingness) | 3 | 3 | `███████████████` 100.0% |  |  |
| **MCPTox** | 2025 | MCP vectors | 1,312 | 101 | `█░░░░░░░░░░░░░░` 7.7% | :construction: open | [GAP-03](https://github.com/taoq-ai/ziran/issues/34) |
| **Agent Security Bench (ASB)** | 2024 | Attack categories | 10 | 11 | `███████████████` 100% | :construction: open | [GAP-01](https://github.com/taoq-ai/ziran/issues/32) |
|  |  | Total vectors | 400 | 639 | `███████████████` 100% |  |  |
|  |  | Utility-under-attack measurement | 1 | 1 | `███████████████` 100.0% |  |  |
| **TensorTrust** | 2024 | Prompt injection vectors | 126,000 | 206 | `░░░░░░░░░░░░░░░` 0.2% | :construction: open | [GAP-16](https://github.com/taoq-ai/ziran/issues/55) |
|  |  | Representative pattern families | — | 11 | _Distinct TensorTrust pattern families covered_ |  |  |
| **WildJailbreak** | 2024 | Jailbreak tactics | 105,000 | 11 | `░░░░░░░░░░░░░░░` 0.0% | :construction: open | [GAP-17](https://github.com/taoq-ai/ziran/issues/56) |
|  |  | WildJailbreak-inspired multi-turn vectors | — | 10 | _Distinct tactic families from WildJailbreak_ |  |  |
| **LLMail-Inject / RAG Poisoning** | 2024 | RAG retrieval-targeted vectors | — | 13 | _Retrieval-ranked payloads across multiple document framings_ | :construction: open | [GAP-13](https://github.com/taoq-ai/ziran/issues/44) |
| **Agent-SafetyBench** | 2024 | Business impact types | 8 | 7 | `█████████████░░` 87.5% | :construction: open | [GAP-07](https://github.com/taoq-ai/ziran/issues/38) |
| **BIPIA** | 2024 | Indirect injection vectors | — | 63 | _Multi-domain benchmark — no fixed target count_ | :construction: open | [GAP-02](https://github.com/taoq-ai/ziran/issues/33) |
| **CyberSecEval** | Meta, 2024 | Code-generation safety vectors | — | 10 | _Code-gen safety + cyber knowledge elicitation families_ | :construction: open | [GAP-18](https://github.com/taoq-ai/ziran/issues/57) |
|  |  | Total library overlap | — | 639 | _Multi-category benchmark — partial overlap_ |  |  |
| **ToolEmu** | 2024 | Tool manipulation vectors | 144 | 176 | `███████████████` 100% | :construction: open | [GAP-19](https://github.com/taoq-ai/ziran/issues/58) |
|  |  | Dedicated sandbox-evasion vectors | — | 10 | _Sandbox-evasion vectors distinct from generic tool manipulation_ |  |  |
| **R-Judge** | 2024 | R-Judge risk types (10) | 10 | 10 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-20](https://github.com/taoq-ai/ziran/issues/59) |
|  |  | Risk scoring detectors | — | 5 | _5 detectors — different approach than interaction records_ |  |  |
| **AILuminate** | MLCommons, 2025 | Resilience gap metric | 1 | 1 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-09](https://github.com/taoq-ai/ziran/issues/40) |
|  |  | Baseline performance measurement | 1 | 1 | `███████████████` 100.0% |  |  |
|  |  | Under-attack performance measurement | 1 | 1 | `███████████████` 100.0% |  |  |
| **ALERT** | 2024 | ALERT micro categories (32) | 32 | 32 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-21](https://github.com/taoq-ai/ziran/issues/60) |
|  |  | Harm categories | — | 11 | _N/A_ |  |  |
| **MITRE ATLAS** | MITRE, 2025 | ATLAS tactics covered | 16 | 16 | `███████████████` 100.0% | :construction: open | [GAP-22](https://github.com/taoq-ai/ziran/issues/61) |
|  |  | ATLAS techniques mapped | 86 | 72 | `█████████████░░` 83.7% |  |  |
|  |  | Agent-specific techniques covered | 14 | 14 | `███████████████` 100.0% |  |  |

## Gap Status

| ID | Gap | Priority | Status |
|----|-----|----------|--------|
| GAP-01 | Benchmark harness | critical | :construction: open ([#32](https://github.com/taoq-ai/ziran/issues/32)) |
| GAP-02 | Indirect prompt injection scale | critical | :construction: open ([#33](https://github.com/taoq-ai/ziran/issues/33)) |
| GAP-03 | MCP tool poisoning | critical | :construction: open ([#34](https://github.com/taoq-ai/ziran/issues/34)) |
| GAP-04 | Quality-aware jailbreak scoring | critical | :white_check_mark: closed ([#35](https://github.com/taoq-ai/ziran/issues/35)) |
| GAP-05 | Utility-under-attack measurement | important | :white_check_mark: closed ([#36](https://github.com/taoq-ai/ziran/issues/36)) |
| GAP-06 | Harmful multi-step task testing | important | :white_check_mark: closed ([#37](https://github.com/taoq-ai/ziran/issues/37)) |
| GAP-07 | Business impact categorization | important | :construction: open ([#38](https://github.com/taoq-ai/ziran/issues/38)) |
| GAP-08 | Jailbreak tactic breadth | important | :white_check_mark: closed ([#39](https://github.com/taoq-ai/ziran/issues/39)) |
| GAP-09 | Resilience gap metric | important | :white_check_mark: closed ([#40](https://github.com/taoq-ai/ziran/issues/40)) |
| GAP-10 | OWASP LLM04 (Model DoS) | lower | :white_check_mark: closed ([#41](https://github.com/taoq-ai/ziran/issues/41)) |
| GAP-11 | OWASP LLM05 (Supply Chain) | lower | :construction: open ([#42](https://github.com/taoq-ai/ziran/issues/42)) |
| GAP-12 | OWASP LLM10 (Model Theft) | lower | :construction: open ([#43](https://github.com/taoq-ai/ziran/issues/43)) |
| GAP-13 | RAG-specific poisoning | lower | :construction: open ([#44](https://github.com/taoq-ai/ziran/issues/44)) |
| GAP-14 | Defense evasion measurement | lower | :construction: open ([#45](https://github.com/taoq-ai/ziran/issues/45)) |
| GAP-15 | JailbreakBench coverage | lower | :white_check_mark: closed ([#54](https://github.com/taoq-ai/ziran/issues/54)) |
| GAP-16 | TensorTrust coverage | lower | :construction: open ([#55](https://github.com/taoq-ai/ziran/issues/55)) |
| GAP-17 | WildJailbreak coverage | lower | :construction: open ([#56](https://github.com/taoq-ai/ziran/issues/56)) |
| GAP-18 | CyberSecEval coverage | lower | :construction: open ([#57](https://github.com/taoq-ai/ziran/issues/57)) |
| GAP-19 | ToolEmu coverage | lower | :construction: open ([#58](https://github.com/taoq-ai/ziran/issues/58)) |
| GAP-20 | R-Judge coverage | lower | :white_check_mark: closed ([#59](https://github.com/taoq-ai/ziran/issues/59)) |
| GAP-21 | ALERT coverage | lower | :white_check_mark: closed ([#60](https://github.com/taoq-ai/ziran/issues/60)) |
| GAP-22 | MITRE ATLAS technique mapping | important | :construction: open ([#61](https://github.com/taoq-ai/ziran/issues/61)) |
| GAP-23 | AgentHarm multi-step vector scale | important | :construction: open ([#131](https://github.com/taoq-ai/ziran/issues/131)) |

## Vector Inventory

### By Attack Category

| Category | Vectors |
|----------|---------|
| prompt_injection | 206 |
| tool_manipulation | 176 |
| indirect_injection | 63 |
| data_exfiltration | 56 |
| privilege_escalation | 35 |
| system_prompt_extraction | 27 |
| memory_poisoning | 20 |
| authorization_bypass | 17 |
| chain_of_thought_manipulation | 15 |
| model_dos | 13 |
| multi_agent | 11 |

### By Tactic

| Tactic | Vectors |
|--------|---------|
| single | 410 |
| context_buildup | 63 |
| crescendo | 38 |
| persona_shift | 23 |
| hypothetical | 17 |
| role_play | 16 |
| distraction | 15 |
| refusal_suppression | 15 |
| code_mode | 14 |
| few_shot | 14 |
| language_switch | 14 |

### By Severity

| Severity | Vectors |
|----------|---------|
| critical | 367 |
| high | 201 |
| low | 1 |
| medium | 70 |

## Scripts

Each script is independently runnable:

```bash
# Individual scripts
uv run python benchmarks/inventory.py
uv run python benchmarks/owasp_coverage.py
uv run python benchmarks/benchmark_comparison.py
uv run python benchmarks/gap_status.py

# Generate all results + markdown report
uv run python benchmarks/generate_all.py

# Write JSON output
uv run python benchmarks/inventory.py --json benchmarks/results/inventory.json
```

## Regenerating

After adding new vectors or closing gaps, regenerate:

```bash
uv run python benchmarks/generate_all.py
```

This updates `benchmarks/results/*.json`, `benchmarks/README.md`, and `docs/reference/benchmarks/coverage-comparison.md`.
