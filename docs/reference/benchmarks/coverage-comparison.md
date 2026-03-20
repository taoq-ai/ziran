# Benchmark Coverage Comparison

Auto-generated comparison of ZIRAN's attack vector library against published AI agent security benchmarks.

*Last updated: 2026-03-21*

## Executive Summary

- **565** attack vectors across **11** attack categories
- **90.0%** OWASP LLM Top 10 coverage (9/10 categories)
- **10** multi-turn jailbreak tactics, **12** encoding types
- **219** multi-turn vectors
- **11** harm categories (AgentHarm-aligned)
- Gap closure: **34.8%** (8/23 gaps closed)

## OWASP LLM Top 10 Coverage

| Code | Category | Vectors | Status |
|------|----------|---------|--------|
| **LLM01** | Prompt Injection | 434 | :white_check_mark: Comprehensive |
| **LLM02** | Insecure Output Handling | 194 | :white_check_mark: Comprehensive |
| **LLM03** | Training Data Poisoning | 15 | :white_check_mark: Strong |
| **LLM04** | Model Denial of Service | 12 | :white_check_mark: Strong |
| **LLM05** | Supply Chain Vulnerabilities | 7 | :large_orange_diamond: Moderate |
| **LLM06** | Sensitive Information Disclosure | 95 | :white_check_mark: Comprehensive |
| **LLM07** | Insecure Plugin Design | 136 | :white_check_mark: Comprehensive |
| **LLM08** | Excessive Agency | 139 | :white_check_mark: Comprehensive |
| **LLM09** | Overreliance | 15 | :white_check_mark: Strong |
| **LLM10** | Unbounded Consumption | — | :construction: Planned |

**Not covered:** LLM10

## Benchmark Comparison

| Benchmark | Venue | Dimension | Target | ZIRAN | Progress | Status | Gap |
|-----------|-------|-----------|-------:|------:|----------|--------|-----|
| **AgentHarm** | ICLR 2025 | Harm categories | 11 | 11 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-06](#37) |
| **AgentHarm** | ICLR 2025 | Multi-step vectors | 440 | 161 | `█████░░░░░░░░░░` 36.6% | :construction: open | [GAP-23](#131) |
| **InjecAgent** | ACL 2024 | Indirect injection vectors | 1,054 | 50 | `█░░░░░░░░░░░░░░` 4.7% | :construction: open | [GAP-02](#33) |
| **AgentDojo** | NeurIPS 2024 | Indirect injection vectors | 629 | 50 | `█░░░░░░░░░░░░░░` 7.9% | :construction: open | [GAP-02](#33) |
|  |  | Utility measurement (baseline + post-attack) | 1 | 1 | `███████████████` 100.0% |  |  |
| **HarmBench** | ICML 2024 | Attack tactics | 18 | 10 | `████████░░░░░░░` 55.6% | :white_check_mark: closed | [GAP-08](#39) |
|  |  | Jailbreak vectors | 510 | 175 | `█████░░░░░░░░░░` 34.3% |  |  |
| **JailbreakBench** | NeurIPS 2024 | JBB categories (10) | 10 | 10 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-15](#54) |
|  |  | Prompt injection vectors | 100 | 175 | `███████████████` 100% |  |  |
| **StrongREJECT** | 2024 | StrongREJECT composite formula | 1 | 1 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-04](#35) |
|  |  | Scoring dimensions (refusal, specificity, convincingness) | 3 | 3 | `███████████████` 100.0% |  |  |
| **MCPTox** | 2025 | MCP vectors | 1,312 | 101 | `█░░░░░░░░░░░░░░` 7.7% | :construction: open | [GAP-03](#34) |
| **Agent Security Bench (ASB)** | 2024 | Attack categories | 10 | 11 | `███████████████` 100% | :construction: open | [GAP-01](#32) |
|  |  | Total vectors | 400 | 565 | `███████████████` 100% |  |  |
|  |  | Utility-under-attack measurement | 1 | 1 | `███████████████` 100.0% |  |  |
| **TensorTrust** | 2024 | Prompt injection vectors | 126,000 | 175 | `░░░░░░░░░░░░░░░` 0.1% | :construction: open | [GAP-16](#55) |
| **WildJailbreak** | 2024 | Jailbreak tactics | 105,000 | 11 | `░░░░░░░░░░░░░░░` 0.0% | :construction: open | [GAP-17](#56) |
| **LLMail-Inject** | 2024 | RAG injection vectors | — | 0 | _Not yet implemented_ | :construction: open | [GAP-13](#44) |
| **Agent-SafetyBench** | 2024 | Business impact types | 8 | 7 | `█████████████░░` 87.5% | :construction: open | [GAP-07](#38) |
| **BIPIA** | 2024 | Indirect injection vectors | — | 50 | _Multi-domain benchmark — no fixed target count_ | :construction: open | [GAP-02](#33) |
| **CyberSecEval** | Meta, 2024 | Total vectors | — | 565 | _Multi-category benchmark — partial overlap_ | :construction: open | [GAP-18](#57) |
| **ToolEmu** | 2024 | Tool manipulation vectors | 144 | 159 | `███████████████` 100% | :construction: open | [GAP-19](#58) |
| **R-Judge** | 2024 | R-Judge risk types (10) | 10 | 10 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-20](#59) |
|  |  | Risk scoring detectors | — | 5 | _5 detectors — different approach than interaction records_ |  |  |
| **AILuminate** | MLCommons, 2025 | Resilience gap metric | — | 0 | _Not yet implemented_ | :construction: open | [GAP-09](#40) |
| **ALERT** | 2024 | ALERT micro categories (32) | 32 | 32 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-21](#60) |
|  |  | Harm categories | — | 11 | _N/A_ |  |  |
| **MITRE ATLAS** | MITRE, 2025 | Attack categories vs tactics | 15 | 11 | `███████████░░░░` 73.3% | :construction: open | [GAP-22](#61) |
|  |  | ATLAS technique mapping | — | 0 | _No atlas_mapping field yet — mapping planned_ |  |  |

## Gap Status Dashboard

See [Gap Analysis](gap-analysis.md) for full details.

| ID | Gap | Priority | Issue | Status |
|----|-----|----------|-------|--------|
| GAP-01 | Benchmark harness | critical | [#32](https://github.com/taoq-ai/ziran/issues/32) | :construction: open |
| GAP-02 | Indirect prompt injection scale | critical | [#33](https://github.com/taoq-ai/ziran/issues/33) | :construction: open |
| GAP-03 | MCP tool poisoning | critical | [#34](https://github.com/taoq-ai/ziran/issues/34) | :construction: open |
| GAP-04 | Quality-aware jailbreak scoring | critical | [#35](https://github.com/taoq-ai/ziran/issues/35) | :white_check_mark: closed |
| GAP-05 | Utility-under-attack measurement | important | [#36](https://github.com/taoq-ai/ziran/issues/36) | :white_check_mark: closed |
| GAP-06 | Harmful multi-step task testing | important | [#37](https://github.com/taoq-ai/ziran/issues/37) | :white_check_mark: closed |
| GAP-07 | Business impact categorization | important | [#38](https://github.com/taoq-ai/ziran/issues/38) | :construction: open |
| GAP-08 | Jailbreak tactic breadth | important | [#39](https://github.com/taoq-ai/ziran/issues/39) | :white_check_mark: closed |
| GAP-09 | Resilience gap metric | important | [#40](https://github.com/taoq-ai/ziran/issues/40) | :construction: open |
| GAP-10 | OWASP LLM04 (Model DoS) | lower | [#41](https://github.com/taoq-ai/ziran/issues/41) | :white_check_mark: closed |
| GAP-11 | OWASP LLM05 (Supply Chain) | lower | [#42](https://github.com/taoq-ai/ziran/issues/42) | :construction: open |
| GAP-12 | OWASP LLM10 (Model Theft) | lower | [#43](https://github.com/taoq-ai/ziran/issues/43) | :construction: open |
| GAP-13 | RAG-specific poisoning | lower | [#44](https://github.com/taoq-ai/ziran/issues/44) | :construction: open |
| GAP-14 | Defense evasion measurement | lower | [#45](https://github.com/taoq-ai/ziran/issues/45) | :construction: open |
| GAP-15 | JailbreakBench coverage | lower | [#54](https://github.com/taoq-ai/ziran/issues/54) | :white_check_mark: closed |
| GAP-16 | TensorTrust coverage | lower | [#55](https://github.com/taoq-ai/ziran/issues/55) | :construction: open |
| GAP-17 | WildJailbreak coverage | lower | [#56](https://github.com/taoq-ai/ziran/issues/56) | :construction: open |
| GAP-18 | CyberSecEval coverage | lower | [#57](https://github.com/taoq-ai/ziran/issues/57) | :construction: open |
| GAP-19 | ToolEmu coverage | lower | [#58](https://github.com/taoq-ai/ziran/issues/58) | :construction: open |
| GAP-20 | R-Judge coverage | lower | [#59](https://github.com/taoq-ai/ziran/issues/59) | :white_check_mark: closed |
| GAP-21 | ALERT coverage | lower | [#60](https://github.com/taoq-ai/ziran/issues/60) | :white_check_mark: closed |
| GAP-22 | MITRE ATLAS technique mapping | important | [#61](https://github.com/taoq-ai/ziran/issues/61) | :construction: open |
| GAP-23 | AgentHarm multi-step vector scale | important | [#131](https://github.com/taoq-ai/ziran/issues/131) | :construction: open |

## Vector Inventory

### By Attack Category

| Category | Vectors |
|----------|---------|
| prompt_injection | 175 |
| tool_manipulation | 159 |
| indirect_injection | 50 |
| data_exfiltration | 49 |
| privilege_escalation | 35 |
| system_prompt_extraction | 25 |
| authorization_bypass | 17 |
| memory_poisoning | 17 |
| chain_of_thought_manipulation | 15 |
| model_dos | 12 |
| multi_agent | 11 |

### By Tactic

| Tactic | Vectors |
|--------|---------|
| single | 346 |
| context_buildup | 62 |
| crescendo | 36 |
| persona_shift | 20 |
| hypothetical | 16 |
| distraction | 15 |
| code_mode | 14 |
| few_shot | 14 |
| language_switch | 14 |
| refusal_suppression | 14 |
| role_play | 14 |

### By Severity

| Severity | Vectors |
|----------|---------|
| critical | 358 |
| high | 159 |
| medium | 48 |

### By Harm Category

| Harm Category | Vectors |
|---------------|---------|
| child_exploitation | 13 |
| cybercrime | 13 |
| disinformation | 13 |
| fraud | 14 |
| harassment | 21 |
| illegal_services | 13 |
| self_harm | 14 |
| sexual_content | 14 |
| substance_abuse | 17 |
| terrorism | 14 |
| weapons | 15 |

---

*Generated by `benchmarks/generate_all.py` on 2026-03-21.*
