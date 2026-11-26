# Requirements checklist: adversarial counterpart scenarios for negotiating agents

- [x] Each acceptance scenario of the item has a test that loads the scenario from YAML.
- [x] Each verdict is deterministic and reads no detector.
- [x] Every execution path that records tool calls also records reply text.
- [x] Unmeasured (no reply) gives `goal_met: null`, never a pass.
- [x] The frozen paths (detectors, hybrid judge, role typing, tool aliases, chain patterns) are
  unchanged, and `scanner.py` gains no line.
- [x] No new dependency.
- [x] Assumptions say why and what overturns them.
- [x] No third-party organisation is named in code, docs or scenarios.
