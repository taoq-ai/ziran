# Benchmark Coverage Comparison

Auto-generated comparison of ZIRAN's attack vector library against published AI agent security benchmarks.

*Last updated: 2026-03-16*

## Executive Summary

- **376** attack vectors across **11** attack categories
- **80.0%** OWASP LLM Top 10 coverage (8/10 categories)
- **10** multi-turn jailbreak tactics, **12** encoding types
- **60** multi-turn vectors
- **11** harm categories (AgentHarm-aligned)
- Gap closure: **22.7%** (5/22 gaps closed)

## OWASP LLM Top 10 Coverage

| Code | Category | Vectors | Status |
|------|----------|---------|--------|
| **LLM01** | Prompt Injection | 224 | :white_check_mark: Comprehensive |
| **LLM02** | Insecure Output Handling | 60 | :white_check_mark: Comprehensive |
| **LLM03** | Training Data Poisoning | 15 | :white_check_mark: Strong |
| **LLM04** | Model Denial of Service | 13 | :white_check_mark: Strong |
| **LLM05** | Supply Chain Vulnerabilities | — | :construction: Planned |
| **LLM06** | Sensitive Information Disclosure | 82 | :white_check_mark: Comprehensive |
| **LLM07** | Insecure Plugin Design | 61 | :white_check_mark: Comprehensive |
| **LLM08** | Excessive Agency | 101 | :white_check_mark: Comprehensive |
| **LLM09** | Overreliance | 19 | :white_check_mark: Strong |
| **LLM10** | Unbounded Consumption | — | :construction: Planned |

**Not covered:** LLM05, LLM10

## Benchmark Comparison

| Benchmark | Venue | Dimension | Target | ZIRAN | Progress | Status | Gap |
|-----------|-------|-----------|-------:|------:|----------|--------|-----|
| **AgentHarm** | ICLR 2025 | Harm categories | 11 | 11 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-06](#37) |
|  |  | Multi-step vectors | 440 | 22 | `█░░░░░░░░░░░░░░` 5.0% |  |  |
| **InjecAgent** | ACL 2024 | Indirect injection vectors | 1,054 | 50 | `█░░░░░░░░░░░░░░` 4.7% | :construction: open | [GAP-02](#33) |
| **AgentDojo** | NeurIPS 2024 | Indirect injection vectors | 629 | 50 | `█░░░░░░░░░░░░░░` 7.9% | :construction: open | [GAP-02](#33) |
| **HarmBench** | ICML 2024 | Attack tactics | 18 | 10 | `████████░░░░░░░` 55.6% | :white_check_mark: closed | [GAP-08](#39) |
|  |  | Jailbreak vectors | 510 | 110 | `███░░░░░░░░░░░░` 21.6% |  |  |
| **JailbreakBench** | NeurIPS 2024 | Prompt injection vectors | 100 | 110 | `███████████████` 100% | :white_check_mark: closed | [GAP-15](#54) |
| **StrongREJECT** | 2024 | Quality-aware scoring | — | 0 | _Binary detection only — no composite scoring yet_ | :construction: open | [GAP-04](#35) |
| **MCPTox** | 2025 | MCP vectors | 1,312 | 10 | `░░░░░░░░░░░░░░░` 0.8% | :construction: open | [GAP-03](#34) |
| **Agent Security Bench (ASB)** | 2024 | Attack categories | 10 | 11 | `███████████████` 100% | :construction: open | [GAP-01](#32) |
|  |  | Total vectors | 400 | 376 | `██████████████░` 94.0% |  |  |
| **TensorTrust** | 2024 | Prompt injection vectors | 126,000 | 110 | `░░░░░░░░░░░░░░░` 0.1% | :construction: open | [GAP-16](#55) |
| **WildJailbreak** | 2024 | Jailbreak tactics | 105,000 | 11 | `░░░░░░░░░░░░░░░` 0.0% | :construction: open | [GAP-17](#56) |
| **LLMail-Inject** | 2024 | RAG injection vectors | — | 0 | _Not yet implemented_ | :construction: open | [GAP-13](#44) |
| **Agent-SafetyBench** | 2024 | Business impact types | 8 | 7 | `█████████████░░` 87.5% | :white_check_mark: closed | [GAP-07](#38) |
| **BIPIA** | 2024 | Indirect injection vectors | — | 50 | _Multi-domain benchmark — no fixed target count_ | :construction: open | [GAP-02](#33) |
| **CyberSecEval** | Meta, 2024 | Total vectors | — | 376 | _Multi-category benchmark — partial overlap_ | :construction: open | [GAP-18](#57) |
| **ToolEmu** | 2024 | Tool manipulation vectors | 144 | 54 | `██████░░░░░░░░░` 37.5% | :construction: open | [GAP-19](#58) |
| **R-Judge** | 2024 | Risk scenario vectors | 569 | 37 | `█░░░░░░░░░░░░░░` 6.5% | :construction: open | [GAP-20](#59) |
|  |  | Risk scoring pipeline | — | 5 | _5 detectors (refusal, indicator, side-effect, authorization, LLM judge)_ |  |  |
| **AILuminate** | MLCommons, 2025 | Resilience gap metric | — | 0 | _Not yet implemented_ | :construction: open | [GAP-09](#40) |
| **ALERT** | 2024 | Harm categories | — | 11 | _Fine-grained taxonomy — not directly comparable_ | :construction: open | [GAP-21](#60) |
| **MITRE ATLAS** | MITRE, 2025 | Attack categories vs tactics | 15 | 11 | `███████████░░░░` 73.3% | :construction: open | [GAP-22](#61) |
|  |  | ATLAS technique mapping | — | 0 | _No atlas_mapping field yet — mapping planned_ |  |  |

## Gap Status Dashboard

See [Gap Analysis](gap-analysis.md) for full details.

| ID | Gap | Priority | Issue | Status |
|----|-----|----------|-------|--------|
| GAP-01 | Benchmark harness | critical | [#32](https://github.com/taoq-ai/ziran/issues/32) | :construction: open |
| GAP-02 | Indirect prompt injection scale | critical | [#33](https://github.com/taoq-ai/ziran/issues/33) | :construction: open |
| GAP-03 | MCP tool poisoning | critical | [#34](https://github.com/taoq-ai/ziran/issues/34) | :construction: open |
| GAP-04 | Quality-aware jailbreak scoring | critical | [#35](https://github.com/taoq-ai/ziran/issues/35) | :construction: open |
| GAP-05 | Utility-under-attack measurement | important | [#36](https://github.com/taoq-ai/ziran/issues/36) | :construction: open |
| GAP-06 | Harmful multi-step task testing | important | [#37](https://github.com/taoq-ai/ziran/issues/37) | :white_check_mark: closed |
| GAP-07 | Business impact categorization | important | [#38](https://github.com/taoq-ai/ziran/issues/38) | :white_check_mark: closed |
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
| GAP-20 | R-Judge coverage | lower | [#59](https://github.com/taoq-ai/ziran/issues/59) | :construction: open |
| GAP-21 | ALERT coverage | lower | [#60](https://github.com/taoq-ai/ziran/issues/60) | :construction: open |
| GAP-22 | MITRE ATLAS technique mapping | important | [#61](https://github.com/taoq-ai/ziran/issues/61) | :construction: open |

## Vector Inventory

### By Attack Category

| Category | Vectors |
|----------|---------|
| prompt_injection | 110 |
| tool_manipulation | 54 |
| indirect_injection | 50 |
| data_exfiltration | 31 |
| privilege_escalation | 28 |
| system_prompt_extraction | 25 |
| authorization_bypass | 21 |
| memory_poisoning | 18 |
| chain_of_thought_manipulation | 15 |
| model_dos | 13 |
| multi_agent | 11 |

### By Tactic

| Tactic | Vectors |
|--------|---------|
| single | 316 |
| context_buildup | 18 |
| crescendo | 17 |
| persona_shift | 4 |
| code_mode | 3 |
| distraction | 3 |
| few_shot | 3 |
| hypothetical | 3 |
| language_switch | 3 |
| refusal_suppression | 3 |
| role_play | 3 |

### By Severity

| Severity | Vectors |
|----------|---------|
| critical | 140 |
| high | 167 |
| low | 1 |
| medium | 68 |

### By Harm Category

| Harm Category | Vectors |
|---------------|---------|
| child_exploitation | 2 |
| cybercrime | 2 |
| disinformation | 2 |
| fraud | 2 |
| harassment | 2 |
| illegal_services | 2 |
| self_harm | 2 |
| sexual_content | 2 |
| substance_abuse | 2 |
| terrorism | 2 |
| weapons | 2 |

---

*Generated by `benchmarks/generate_all.py` on 2026-03-16.*
