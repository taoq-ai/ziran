# Feature Specification: A chain's data classes include what its source tools reach

**Feature Branch**: `feat/chain-source-data`
**Created**: 2026-11-25
**Status**: Active
**Plan item**: C-CHAIN-SOURCE-DATA (goal G-c)

## The promise in our own words

A chain's blast radius (spec 091) is walked only from the chain's last tool, forward. Remote
probe discovery adds no agent node and no agent-to-tool edge, and links each dangerous tool
only to the shared `sensitive_data` node. So for an exfiltration chain such as
`read_inbox -> send_email`, the walk from `send_email` never reaches `read_inbox`, and a tag
the operator put on `read_inbox` (say `pii`) never shows on the chain. The report reads
"none tagged" for data the chain's source reads.

After the change the walk also starts at the chain's source tools (`chain.tools[:-1]`). The
existing walk already adds the agents that hold a start tool (`USES_TOOL`) and follows their
tools, so where an adapter reports agents, their tools are reached as before. Tagged data a
source tool holds shows on the chain; chains whose classes came from the last tool keep them.

## Acceptance scenarios

1. Given a `read_inbox -> send_email` chain on a probe-discovered agent with `read_inbox`
   tagged `pii`, when the scan result is built, then the chain's data classes include `pii`
   (demonstrated when a recorded call named `read_inbox`, reachable otherwise).
2. Given a `read_file -> http_request` chain with `sensitive_data` tagged `secret`, when the
   result is built, then its data classes are exactly `secret`.
3. Given a probe-discovered agent where `sensitive_data` is tagged `secret` and a tool no
   chain holds is tagged `pii`, then every chain reads `secret` only: sharing the
   `sensitive_data` node adds no class.

## Requirements

- FR-001: `ResultBuilder._fill_blast_radius` walks once per distinct last tool, from the last
  tool and the source tools of every chain that ends at it.
- FR-002: `CampaignResult.blast_radius` stays keyed by last tool; a chain's radius is still
  `blast_radius[chain["tools"][-1]]`, so SARIF, the reports and other readers are unchanged.
- FR-003: no change to the chain rules, role typing, tool aliases, detectors or the walk
  itself (`blast_radius()`).

## Assumptions

- Chosen fix: seed the walk from the chain's tools (gate option a), not an agent-to-tool edge
  per probe-discovered tool (option b). Why: (a) is a few lines in the result builder and
  touches no graph shape; (b) adds an agent node and edges that the trifecta scope, attack
  path search, graph stats and the chain benchmarks also read, so it could move chain
  findings. What would overturn it: data a tool outside every chain holds is meant to show
  (then option b is needed).
- Chains that share a last tool share one radius, walked from all their source tools, so the
  output stays one radius per last tool (linear). A chain then shows data another chain's
  source holds when both end at the same tool. That data can leave through the same tool, and
  an agent with reported structure already shows all its tools' data through `USES_TOOL`.
  What would overturn it: a reader that needs a per-chain radius; then key by chain.
- Source tools now count in the radius lists too (an `exec` source shows under `exec`). They
  are part of the chain, so this is what the chain reaches.

## Out of scope

A tag on a tool no chain holds and no edge reaches (for example a lookup tool that probe
discovery marks as a skill) still does not show; that needs agent-to-tool edges in discovery.
