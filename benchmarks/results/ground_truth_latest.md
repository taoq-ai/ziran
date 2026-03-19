# Ground Truth Benchmark Results

**Date:** 2026-03-19 10:39:38 UTC
**Dataset:** 14 agents, 54 scenarios (29 TP, 25 TN)

## Summary

| Component | TP | FP | FN | Precision | Recall | F1 |
|---|--:|--:|--:|--:|--:|--:|
| Chain Analyzer | 5 | 0 | 14 | 100.0% | 26.3% | 41.7% |
| Skill CVE Matcher | 1 | 1 | 24 | 50.0% | 4.0% | 7.4% |
| Tool Classifier | 26 | 12 | 1 | 68.4% | 96.3% | 80.0% |
| Scenario Verdict | 20 | 9 | 9 | 69.0% | 69.0% | 69.0% |
| **Macro Average** | | | | **71.8%** | **48.9%** | **49.5%** |

