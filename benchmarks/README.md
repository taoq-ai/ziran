# ZIRAN Benchmark Coverage

How ZIRAN's attack vector library compares against published AI agent security benchmarks.

## Current State

| Metric | Value |
|--------|-------|
| Attack vectors | **565** |
| Attack categories | **11** |
| OWASP LLM Top 10 | **90.0%** (9/10) |
| Multi-turn tactics | **10** |
| Encoding types | **12** |
| Benchmarks analyzed | **20** |
| Gap closure | **34.8%** (8/23) |

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
| **LLM10** | Unbounded Consumption | — | :construction: Planned ([#43](https://github.com/taoq-ai/ziran/issues/43)) |

## Benchmark Comparison

| Benchmark | Venue | Dimension | Target | ZIRAN | Progress | Status | Gap |
|-----------|-------|-----------|-------:|------:|----------|--------|-----|
| **AgentHarm** | ICLR 2025 | Harm categories | 11 | 11 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-06](https://github.com/taoq-ai/ziran/issues/37) |
| **AgentHarm** | ICLR 2025 | Multi-step vectors | 440 | 161 | `█████░░░░░░░░░░` 36.6% | :construction: open | [GAP-23](https://github.com/taoq-ai/ziran/issues/131) |
| **InjecAgent** | ACL 2024 | Indirect injection vectors | 1,054 | 50 | `█░░░░░░░░░░░░░░` 4.7% | :construction: open | [GAP-02](https://github.com/taoq-ai/ziran/issues/33) |
| **AgentDojo** | NeurIPS 2024 | Indirect injection vectors | 629 | 50 | `█░░░░░░░░░░░░░░` 7.9% | :construction: open | [GAP-02](https://github.com/taoq-ai/ziran/issues/33) |
| **HarmBench** | ICML 2024 | Attack tactics | 18 | 10 | `████████░░░░░░░` 55.6% | :white_check_mark: closed | [GAP-08](https://github.com/taoq-ai/ziran/issues/39) |
|  |  | Jailbreak vectors | 510 | 175 | `█████░░░░░░░░░░` 34.3% |  |  |
| **JailbreakBench** | NeurIPS 2024 | JBB categories (10) | 10 | 10 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-15](https://github.com/taoq-ai/ziran/issues/54) |
|  |  | Prompt injection vectors | 100 | 175 | `███████████████` 100% |  |  |
| **StrongREJECT** | 2024 | StrongREJECT composite formula | 1 | 1 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-04](https://github.com/taoq-ai/ziran/issues/35) |
|  |  | Scoring dimensions (refusal, specificity, convincingness) | 3 | 3 | `███████████████` 100.0% |  |  |
| **MCPTox** | 2025 | MCP vectors | 1,312 | 101 | `█░░░░░░░░░░░░░░` 7.7% | :construction: open | [GAP-03](https://github.com/taoq-ai/ziran/issues/34) |
| **Agent Security Bench (ASB)** | 2024 | Attack categories | 10 | 11 | `███████████████` 100% | :construction: open | [GAP-01](https://github.com/taoq-ai/ziran/issues/32) |
|  |  | Total vectors | 400 | 565 | `███████████████` 100% |  |  |
| **TensorTrust** | 2024 | Prompt injection vectors | 126,000 | 175 | `░░░░░░░░░░░░░░░` 0.1% | :construction: open | [GAP-16](https://github.com/taoq-ai/ziran/issues/55) |
| **WildJailbreak** | 2024 | Jailbreak tactics | 105,000 | 11 | `░░░░░░░░░░░░░░░` 0.0% | :construction: open | [GAP-17](https://github.com/taoq-ai/ziran/issues/56) |
| **LLMail-Inject** | 2024 | RAG injection vectors | — | 0 | _Not yet implemented_ | :construction: open | [GAP-13](https://github.com/taoq-ai/ziran/issues/44) |
| **Agent-SafetyBench** | 2024 | Business impact types | 8 | 7 | `█████████████░░` 87.5% | :construction: open | [GAP-07](https://github.com/taoq-ai/ziran/issues/38) |
| **BIPIA** | 2024 | Indirect injection vectors | — | 50 | _Multi-domain benchmark — no fixed target count_ | :construction: open | [GAP-02](https://github.com/taoq-ai/ziran/issues/33) |
| **CyberSecEval** | Meta, 2024 | Total vectors | — | 565 | _Multi-category benchmark — partial overlap_ | :construction: open | [GAP-18](https://github.com/taoq-ai/ziran/issues/57) |
| **ToolEmu** | 2024 | Tool manipulation vectors | 144 | 159 | `███████████████` 100% | :construction: open | [GAP-19](https://github.com/taoq-ai/ziran/issues/58) |
| **R-Judge** | 2024 | R-Judge risk types (10) | 10 | 10 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-20](https://github.com/taoq-ai/ziran/issues/59) |
|  |  | Risk scoring detectors | — | 5 | _5 detectors — different approach than interaction records_ |  |  |
| **AILuminate** | MLCommons, 2025 | Resilience gap metric | 1 | 1 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-09](https://github.com/taoq-ai/ziran/issues/40) |
|  |  | Baseline performance measurement | 1 | 1 | `███████████████` 100.0% |  |  |
|  |  | Under-attack performance measurement | 1 | 1 | `███████████████` 100.0% |  |  |
| **ALERT** | 2024 | ALERT micro categories (32) | 32 | 32 | `███████████████` 100.0% | :white_check_mark: closed | [GAP-21](https://github.com/taoq-ai/ziran/issues/60) |
|  |  | Harm categories | — | 11 | _N/A_ |  |  |
| **MITRE ATLAS** | MITRE, 2025 | Attack categories vs tactics | 15 | 11 | `███████████░░░░` 73.3% | :construction: open | [GAP-22](https://github.com/taoq-ai/ziran/issues/61) |
|  |  | ATLAS technique mapping | — | 0 | _No atlas_mapping field yet — mapping planned_ |  |  |

## Gap Status

| ID | Gap | Priority | Status |
|----|-----|----------|--------|
| GAP-01 | Benchmark harness | critical | :construction: open ([#32](https://github.com/taoq-ai/ziran/issues/32)) |
| GAP-02 | Indirect prompt injection scale | critical | :construction: open ([#33](https://github.com/taoq-ai/ziran/issues/33)) |
| GAP-03 | MCP tool poisoning | critical | :construction: open ([#34](https://github.com/taoq-ai/ziran/issues/34)) |
| GAP-04 | Quality-aware jailbreak scoring | critical | :white_check_mark: closed ([#35](https://github.com/taoq-ai/ziran/issues/35)) |
| GAP-05 | Utility-under-attack measurement | important | :construction: open ([#36](https://github.com/taoq-ai/ziran/issues/36)) |
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
