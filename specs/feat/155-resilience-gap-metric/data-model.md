# Data Model: Resilience Gap Metric

## Entity: ResilienceMetrics (extended)

### Existing Fields (unchanged)
- `total_attacks: int` — Total number of attacks in campaign
- `successful_attacks: int` — Number of attacks that succeeded
- `attack_resilience_rate: float [0, 1]` — 1 - ASR (fraction of attacks blocked)
- `trust_degradation: float [0, 1]` — Drop in trust score from first to last phase
- `resilience_score: float [0, 1]` — Weighted composite (70% attack resilience + 30% trust preservation)

### New Fields
- `baseline_performance: float [0, 1]` — Expected agent performance without attacks (default: 1.0)
- `under_attack_performance: float [0, 1]` — Agent performance during attack campaign (default: 1.0)
- `resilience_gap: float [0, 1]` — Delta: baseline - under_attack (default: 0.0)

### Computation
```
baseline_performance = phases[0].trust_score if phases else 1.0
under_attack_performance = attack_resilience_rate * (1 - trust_degradation)
resilience_gap = max(0, min(1, baseline_performance - under_attack_performance))
```

### Validation Rules
- All new fields: `ge=0.0, le=1.0`
- `resilience_gap` MUST equal `baseline_performance - under_attack_performance` (clamped)
- Fields have defaults for backward compatibility
