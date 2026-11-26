# Requirements checklist: attacker-LLM campaigns (TAP tree search, live crescendo)

- [x] Each acceptance scenario of the item has a test that loads the example scenario from YAML.
- [x] The new `campaign` field loads through `AttackLibrary` from YAML, with a test.
- [x] Every loop has a bound in the model (width, branching, depth, turns, max_nodes), and each
  bound has a test that stops on it, plus the budget and the deadline.
- [x] The stop on a met goal uses `goal_status` on the same turns `judge_goal` reads.
- [x] Node ids are deterministic, and a cassette replay through `RecordReplayClient` gives an
  equal tree.
- [x] No node and no answered reply gives `outcome: unmeasured`, never a pass.
- [x] Attacker vectors are found by `is_pair`, so the not-run drop of F-SCAN-ATTACKER-FLAG covers
  them; no CLI flag is added.
- [x] The frozen paths (detectors, hybrid judge and prompts, `review_evidence`, role typing, tool
  aliases, chain patterns) are unchanged, and `scanner.py` gains no line.
- [x] No new dependency.
- [x] Assumptions say why and what overturns them.
- [x] No third-party organisation is named in code, docs or scenarios.
