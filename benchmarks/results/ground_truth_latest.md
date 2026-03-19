# Ground Truth Benchmark Results

**Date:** 2026-03-19 14:09:13 UTC
**Dataset:** 14 agents, 54 scenarios (29 TP, 25 TN)

## Summary

| Component | TP | FP | FN | Precision | Recall | F1 |
|---|--:|--:|--:|--:|--:|--:|
| Chain Analyzer | 12 | 0 | 7 | 100.0% | 63.2% | 77.4% |
| Skill CVE Matcher | 1 | 1 | 24 | 50.0% | 4.0% | 7.4% |
| Tool Classifier | 26 | 12 | 1 | 68.4% | 96.3% | 80.0% |
| Scenario Verdict | 27 | 15 | 2 | 64.3% | 93.1% | 76.1% |
| **Macro Average** | | | | **70.7%** | **64.1%** | **60.2%** |

