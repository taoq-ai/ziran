# ZIRAN Benchmark Coverage

How ZIRAN's attack vector library compares against published AI agent security benchmarks.

## Current State

| Metric | Value |
|--------|-------|
| Attack vectors | **240** |
| Attack categories | **10** |
| OWASP LLM Top 10 | **70%** (7/10) |
| Multi-turn tactics | **10** |
| Encoding types | **12** |
| Benchmarks analyzed | **18** |
| Gap closure | **29%** (4/14) |

## OWASP LLM Top 10 Coverage

| Code | Category | Vectors | Status |
|------|----------|---------|--------|
| **LLM01** | Prompt Injection | 136 | :white_check_mark: Comprehensive |
| **LLM02** | Insecure Output Handling | 31 | :white_check_mark: Strong |
| **LLM03** | Training Data Poisoning | 15 | :white_check_mark: Strong |
| **LLM04** | Model Denial of Service | — | :construction: Planned ([#41](https://github.com/taoq-ai/ziran/issues/41)) |
| **LLM05** | Supply Chain Vulnerabilities | — | :construction: Planned ([#42](https://github.com/taoq-ai/ziran/issues/42)) |
| **LLM06** | Sensitive Information Disclosure | 72 | :white_check_mark: Comprehensive |
| **LLM07** | Insecure Plugin Design | 44 | :white_check_mark: Comprehensive |
| **LLM08** | Excessive Agency | 73 | :white_check_mark: Comprehensive |
| **LLM09** | Overreliance | 15 | :white_check_mark: Strong |
| **LLM10** | Unbounded Consumption | — | :construction: Planned ([#43](https://github.com/taoq-ai/ziran/issues/43)) |

## Benchmark Comparison

| Benchmark | Venue | Test Cases | ZIRAN Status | Gap |
|-----------|-------|------------|-------------|-----|
| **AgentHarm** | ICLR 2025 | 440 | :white_check_mark: closed | [GAP-06](https://github.com/taoq-ai/ziran/issues/37) |
| **InjecAgent** | ACL 2024 | 1,054 | :construction: open | [GAP-02](https://github.com/taoq-ai/ziran/issues/33) |
| **AgentDojo** | NeurIPS 2024 | 629 | :construction: open | [GAP-02](https://github.com/taoq-ai/ziran/issues/33) |
| **HarmBench** | ICML 2024 | 510 | :white_check_mark: closed | [GAP-08](https://github.com/taoq-ai/ziran/issues/39) |
| **JailbreakBench** | NeurIPS 2024 | 100 | :large_orange_diamond: partial | — |
| **StrongREJECT** | 2024 | — | :construction: open | [GAP-04](https://github.com/taoq-ai/ziran/issues/35) |
| **MCPTox** | 2025 | 1,312 | :construction: open | [GAP-03](https://github.com/taoq-ai/ziran/issues/34) |
| **ASB** | 2024 | 400 | :construction: open | [GAP-01](https://github.com/taoq-ai/ziran/issues/32) |
| **TensorTrust** | 2024 | 126,000 | :red_circle: minimal | — |
| **WildJailbreak** | 2024 | 105,000 | :red_circle: minimal | — |
| **LLMail-Inject** | 2024 | — | :construction: open | [GAP-13](https://github.com/taoq-ai/ziran/issues/44) |
| **Agent-SafetyBench** | 2024 | 2,000 | :white_check_mark: closed | [GAP-07](https://github.com/taoq-ai/ziran/issues/38) |
| **BIPIA** | 2024 | — | :construction: open | [GAP-02](https://github.com/taoq-ai/ziran/issues/33) |
| **CyberSecEval** | Meta, 2024 | — | :large_orange_diamond: partial | — |
| **ToolEmu** | 2024 | 144 | :large_orange_diamond: partial | — |
| **R-Judge** | 2024 | 569 | :large_orange_diamond: partial | — |
| **AILuminate** | MLCommons, 2025 | — | :construction: open | [GAP-09](https://github.com/taoq-ai/ziran/issues/40) |
| **ALERT** | 2024 | 45,000 | :large_orange_diamond: partial | — |

## Gap Status

| ID | Gap | Priority | Status |
|----|-----|----------|--------|
| GAP-01 | Benchmark harness | critical | :construction: open ([#32](https://github.com/taoq-ai/ziran/issues/32)) |
| GAP-02 | Indirect prompt injection scale | critical | :construction: open ([#33](https://github.com/taoq-ai/ziran/issues/33)) |
| GAP-03 | MCP tool poisoning | critical | :construction: open ([#34](https://github.com/taoq-ai/ziran/issues/34)) |
| GAP-04 | Quality-aware jailbreak scoring | critical | :construction: open ([#35](https://github.com/taoq-ai/ziran/issues/35)) |
| GAP-05 | Utility-under-attack measurement | important | :construction: open ([#36](https://github.com/taoq-ai/ziran/issues/36)) |
| GAP-06 | Harmful multi-step task testing | important | :white_check_mark: closed ([#37](https://github.com/taoq-ai/ziran/issues/37)) |
| GAP-07 | Business impact categorization | important | :white_check_mark: closed ([#38](https://github.com/taoq-ai/ziran/issues/38)) |
| GAP-08 | Jailbreak tactic breadth | important | :white_check_mark: closed ([#39](https://github.com/taoq-ai/ziran/issues/39)) |
| GAP-09 | Resilience gap metric | important | :construction: open ([#40](https://github.com/taoq-ai/ziran/issues/40)) |
| GAP-10 | OWASP LLM04 (Model DoS) | lower | :white_check_mark: closed ([#41](https://github.com/taoq-ai/ziran/issues/41)) |
| GAP-11 | OWASP LLM05 (Supply Chain) | lower | :construction: open ([#42](https://github.com/taoq-ai/ziran/issues/42)) |
| GAP-12 | OWASP LLM10 (Model Theft) | lower | :construction: open ([#43](https://github.com/taoq-ai/ziran/issues/43)) |
| GAP-13 | RAG-specific poisoning | lower | :construction: open ([#44](https://github.com/taoq-ai/ziran/issues/44)) |
| GAP-14 | Defense evasion measurement | lower | :construction: open ([#45](https://github.com/taoq-ai/ziran/issues/45)) |

## Vector Inventory

### By Attack Category

| Category | Vectors |
|----------|---------|
| indirect_injection | 50 |
| prompt_injection | 35 |
| privilege_escalation | 25 |
| system_prompt_extraction | 25 |
| tool_manipulation | 23 |
| data_exfiltration | 22 |
| authorization_bypass | 17 |
| memory_poisoning | 17 |
| chain_of_thought_manipulation | 15 |
| multi_agent | 11 |

### By Tactic

| Tactic | Vectors |
|--------|---------|
| single | 205 |
| crescendo | 6 |
| context_buildup | 4 |
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
| critical | 96 |
| high | 104 |
| medium | 40 |

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

This updates `benchmarks/results/*.json` and `docs/reference/benchmarks/coverage-comparison.md`.
