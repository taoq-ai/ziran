# Ground Truth Benchmark Results

**Date:** 2026-03-19 14:35:41 UTC
**Dataset:** 14 agents, 54 scenarios (29 TP, 25 TN)

## Summary

| Component | TP | FP | FN | Precision | Recall | F1 |
|---|--:|--:|--:|--:|--:|--:|
| Chain Analyzer | 5 | 0 | 14 | 100.0% | 26.3% | 41.7% |
| Skill CVE Matcher | 15 | 21 | 4 | 41.7% | 78.9% | 54.5% |
| Tool Classifier | 26 | 12 | 1 | 68.4% | 96.3% | 80.0% |
| Scenario Verdict | 29 | 3 | 0 | 90.6% | 100.0% | 95.1% |
| **Macro Average** | | | | **75.2%** | **75.4%** | **67.8%** |

