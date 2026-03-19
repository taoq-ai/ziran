# Ground Truth Benchmark Results

**Date:** 2026-03-19 13:38:33 UTC
**Dataset:** 14 agents, 54 scenarios (29 TP, 25 TN)

## Summary

| Component | TP | FP | FN | Precision | Recall | F1 |
|---|--:|--:|--:|--:|--:|--:|
| Chain Analyzer | 5 | 0 | 14 | 100.0% | 26.3% | 41.7% |
| Skill CVE Matcher | 15 | 21 | 4 | 41.7% | 78.9% | 54.5% |
| Tool Classifier | 26 | 12 | 1 | 68.4% | 96.3% | 80.0% |
| Scenario Verdict | 29 | 18 | 0 | 61.7% | 100.0% | 76.3% |
| **Macro Average** | | | | **67.9%** | **75.4%** | **63.1%** |

