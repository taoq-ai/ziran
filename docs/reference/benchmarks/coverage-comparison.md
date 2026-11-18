# Benchmark Coverage Comparison

Auto-generated comparison of ZIRAN's attack vector library against published AI agent security benchmarks.

*Last updated: 2026-11-18*

## Executive Summary

- **677** attack vectors across **11** attack categories
- **100.0%** OWASP LLM Top 10 coverage (10/10 categories)
- **10** multi-turn jailbreak tactics, **12** encoding types
- **229** multi-turn vectors
- **12** long-context `many-shot` jailbreak vectors
- **8** MCP server-initiated vectors (sampling, elicitation, roots), sent by `ziran mcp-hostile-server`, never by a scan
- **11** harm categories (AgentHarm-aligned)
- Gap closure: **39.1%** (9/23 gaps closed)

## OWASP LLM Top 10 Coverage

| Code | Category | Vectors | Status |
|------|----------|---------|--------|
| **LLM01** | Prompt Injection | 485 | :white_check_mark: Comprehensive |
| **LLM02** | Insecure Output Handling | 202 | :white_check_mark: Comprehensive |
| **LLM03** | Training Data Poisoning | 19 | :white_check_mark: Strong |
| **LLM04** | Model Denial of Service | 14 | :white_check_mark: Strong |
| **LLM05** | Supply Chain Vulnerabilities | 18 | :white_check_mark: Strong |
| **LLM06** | Sensitive Information Disclosure | 116 | :white_check_mark: Comprehensive |
| **LLM07** | Insecure Plugin Design | 164 | :white_check_mark: Comprehensive |
| **LLM08** | Excessive Agency | 168 | :white_check_mark: Comprehensive |
| **LLM09** | Overreliance | 15 | :white_check_mark: Strong |
| **LLM10** | Unbounded Consumption | 10 | :white_check_mark: Strong |

## MITRE ATLAS Coverage

Technique mapping snapshot date: **2025-10-01** (see [atlas-mapping.md](atlas-mapping.md) for methodology).

- **75/88** ATLAS techniques represented in the library
- **14/14** agent-specific techniques covered (from the October 2025 ATLAS release)
- **677/677** vectors carry an ATLAS mapping

### Coverage by Tactic

| Tactic | Name | Techniques | Vectors |
|--------|------|-----------:|--------:|
| **AML.TA0000** | AI Model Access | 3/4 | 927 |
| **AML.TA0001** | AI Attack Staging | 7/7 | 626 |
| **AML.TA0002** | Reconnaissance | 4/6 | 25 |
| **AML.TA0003** | Resource Development | 6/12 | 433 |
| **AML.TA0004** | Initial Access | 9/11 | 192 |
| **AML.TA0005** | Execution | 5/6 | 805 |
| **AML.TA0006** | Persistence | 8/8 | 271 |
| **AML.TA0007** | Defense Evasion | 6/6 | 385 |
| **AML.TA0008** | Discovery | 7/7 | 173 |
| **AML.TA0009** | Collection | 3/4 | 76 |
| **AML.TA0010** | Exfiltration | 7/7 | 358 |
| **AML.TA0011** | Impact | 14/14 | 664 |
| **AML.TA0012** | Privilege Escalation | 4/4 | 596 |
| **AML.TA0013** | Credential Access | 1/1 | 28 |
| **AML.TA0014** | Command and Control | 1/1 | 163 |
| **AML.TA0015** | Lateral Movement | 2/2 | 40 |

## Benchmark Comparison

| Benchmark | Venue | Dimension | Target | ZIRAN | Progress | Status | Gap |
|-----------|-------|-----------|-------:|------:|----------|--------|-----|
| **AgentHarm** | ICLR 2025 | Harm categories | 11 | 11 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-06](#37) |
| **AgentHarm** | ICLR 2025 | Multi-step vectors | 440 | 173 | `██████░░░░░░░░░` 39.3% | :construction: open | [GAP-23](#131) |
| **InjecAgent** | ACL 2024 | Indirect injection vectors | 1,054 | 65 | `█░░░░░░░░░░░░░░` 6.2% | :construction: open | [GAP-02](#33) |
| **AgentDojo** | NeurIPS 2024 | Indirect injection vectors | 629 | 65 | `██░░░░░░░░░░░░░` 10.3% | :construction: open | [GAP-02](#33) |
|  |  | Utility measurement (baseline + post-attack) | 1 | 1 | `███████████████` 100.0% |  |  |
| **HarmBench** | ICML 2024 | Attack tactics | 18 | 10 | `████████░░░░░░░` 55.6% | :white_check_mark: closed | [GAP-08](#39) |
|  |  | Jailbreak vectors | 510 | 220 | `██████░░░░░░░░░` 43.1% |  |  |
| **JailbreakBench** | NeurIPS 2024 | JBB categories (10) | 10 | 10 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-15](#54) |
|  |  | Prompt injection vectors | 100 | 220 | `███████████████` 100% |  |  |
| **StrongREJECT** | 2024 | StrongREJECT composite formula | 1 | 1 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-04](#35) |
|  |  | Scoring dimensions (refusal, specificity, convincingness) | 3 | 3 | `███████████████` 100.0% |  |  |
| **MCPTox** | 2025 | MCP vectors | 1,312 | 111 | `█░░░░░░░░░░░░░░` 8.5% | :construction: open | [GAP-03](#34) |
| **Agent Security Bench (ASB)** | 2024 | Attack categories | 10 | 11 | `███████████████` 100% | :construction: open | [GAP-01](#32) |
|  |  | Total vectors | 400 | 677 | `███████████████` 100% |  |  |
|  |  | Utility-under-attack measurement | 1 | 1 | `███████████████` 100.0% |  |  |
| **TensorTrust** | 2024 | Prompt injection vectors | 126,000 | 220 | `░░░░░░░░░░░░░░░` 0.2% | :construction: open | [GAP-16](#55) |
|  |  | Representative pattern families | — | 11 | _Distinct TensorTrust pattern families covered_ |  |  |
| **WildJailbreak** | 2024 | Jailbreak tactics | 105,000 | 11 | `░░░░░░░░░░░░░░░` 0.0% | :construction: open | [GAP-17](#56) |
|  |  | WildJailbreak-inspired multi-turn vectors | — | 10 | _Distinct tactic families from WildJailbreak_ |  |  |
| **LLMail-Inject / RAG Poisoning** | 2024 | RAG retrieval-targeted vectors | — | 13 | _Retrieval-ranked payloads across multiple document framings_ | :construction: open | [GAP-13](#44) |
| **Agent-SafetyBench** | 2024 | Business impact types | 8 | 7 | `█████████████░░` 87.5% | :construction: open | [GAP-07](#38) |
| **BIPIA** | 2024 | Indirect injection vectors | — | 65 | _Multi-domain benchmark — no fixed target count_ | :construction: open | [GAP-02](#33) |
| **CyberSecEval** | Meta, 2024 | Code-generation safety vectors | — | 10 | _Code-gen safety + cyber knowledge elicitation families_ | :construction: open | [GAP-18](#57) |
|  |  | Total library overlap | — | 677 | _Multi-category benchmark — partial overlap_ |  |  |
| **ToolEmu** | 2024 | Tool manipulation vectors | 144 | 188 | `███████████████` 100% | :construction: open | [GAP-19](#58) |
|  |  | Dedicated sandbox-evasion vectors | — | 10 | _Sandbox-evasion vectors distinct from generic tool manipulation_ |  |  |
| **R-Judge** | 2024 | R-Judge risk types (10) | 10 | 10 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-20](#59) |
|  |  | Risk scoring detectors | — | 5 | _5 detectors — different approach than interaction records_ |  |  |
| **AILuminate** | MLCommons, 2025 | Resilience gap metric | 1 | 1 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-09](#40) |
|  |  | Baseline performance measurement | 1 | 1 | `███████████████` 100.0% |  |  |
|  |  | Under-attack performance measurement | 1 | 1 | `███████████████` 100.0% |  |  |
| **ALERT** | 2024 | ALERT micro categories (32) | 32 | 32 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-21](#60) |
|  |  | Harm categories | — | 11 | _N/A_ |  |  |
| **MITRE ATLAS** | MITRE, 2025 | ATLAS tactics covered | 16 | 16 | `███████████████` 100.0% | :construction: open | [GAP-22](#61) |
|  |  | ATLAS techniques mapped | 88 | 75 | `█████████████░░` 85.2% |  |  |
|  |  | Agent-specific techniques covered | 14 | 14 | `███████████████` 100.0% |  |  |

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
| GAP-09 | Resilience gap metric | important | [#40](https://github.com/taoq-ai/ziran/issues/40) | :white_check_mark: closed |
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
| prompt_injection | 220 |
| tool_manipulation | 188 |
| indirect_injection | 65 |
| data_exfiltration | 60 |
| privilege_escalation | 41 |
| system_prompt_extraction | 27 |
| memory_poisoning | 20 |
| authorization_bypass | 17 |
| chain_of_thought_manipulation | 15 |
| model_dos | 13 |
| multi_agent | 11 |

### By Tactic

| Tactic | Vectors |
|--------|---------|
| single | 448 |
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
| critical | 383 |
| high | 220 |
| low | 1 |
| medium | 73 |

### By Harm Category

| Harm Category | Vectors |
|---------------|---------|
| child_exploitation | 13 |
| cybercrime | 15 |
| disinformation | 15 |
| fraud | 16 |
| harassment | 23 |
| illegal_services | 15 |
| self_harm | 14 |
| sexual_content | 14 |
| substance_abuse | 17 |
| terrorism | 14 |
| weapons | 17 |

## Detection Accuracy

Per-detector and pipeline precision/recall/F1 over the labelled detection dataset — see [detection-accuracy.md](detection-accuracy.md) for methodology and validity caveats. Run with `benchmarks/detection_accuracy.py`.

| Detector | F1 |
|----------|-----|
| refusal | 0.90 |
| indicator | 1.00 |
| side_effect | 1.00 |
| llm_judge | 1.00 |
| **pipeline** | **1.00** |

Baseline over 228 labelled examples. The refusal detector's F1 is bounded by precision (false-alarms on atypically-phrased refusals), not missed compromises.

## Pentest Agent vs Rule-Based Scanner

Head-to-head on ground-truth targets — what each tool catches vs what it costs. See [pentest-evaluation.md](pentest-evaluation.md). Run with `benchmarks/pentest_vs_scanner.py`.

:construction: US1 harness shipped; agent cassettes are seed-only pending the live `--mode record` path. On the simulated targets the rule-based scanner reaches full ground-truth recall at ≈0 token cost; novel-discovery is only measurable on the real example agent.

---

*Generated by `benchmarks/generate_all.py` on 2026-11-18.*
