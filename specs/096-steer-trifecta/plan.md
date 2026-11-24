# Implementation Plan: aim chain vectors at the lethal trifecta, refuse credential files, swap whole host names

**Branch**: `feat/096-steer-trifecta` | **Spec**: [spec.md](spec.md)

## Technical Context

Python 3.11+ (CI matrix 3.11, 3.12, 3.13), stdlib `re`; no new dependencies. Touched:
`ziran/application/agent_scanner/chain_targeting.py` (316 lines, limit 400 in
`tests/unit/application/test_scanner_size.py`), `ziran/application/knowledge_graph/tool_aliases.py`,
`tests/unit/application/test_chain_targeting.py`, `tests/unit/test_tool_aliases.py`.
`scanner.py` and `attack_executor.py` are not touched.

## Design

- Family table: the exfiltration row's prefixes gain `trifecta`. `_family` already matches a
  prefix on any `_` token of the chain type, so `lethal_trifecta` and
  `lethal_trifecta_delegated` take the exfiltration row, and `plan` already keeps one ranked pool
  per row, so the trifecta and exfiltration chains share it.
- Ends: `_leg(chain, leg)` reads the first tool of an evidence list (`find_trifectas` and
  `_delegated` both write `private_data` and `egress` lists). Any other chain has no such key and
  keeps `tools[0]` and `tools[-1]`.
- Mail sink: when the sink's prompt name contains `mail`, the family task's `ENDPOINT` becomes
  `MAILBOX` (`reports@reports.example.invalid`). The `{url}` fill stays the upload URL.
- Secret paths: `tool_aliases._SECRET_PATH` becomes public `SECRET_PATH` with `/etc/shadow\b`.
  `_names_secret` first checks each token of the raw text (split on whitespace, quotes,
  brackets and `,;:=?!*`, trailing dots dropped) against it. `_resource` and `_render` already
  call `_names_secret`, so both gain the check with no other change.
- Swap: one anchored, case-insensitive `re.sub` per mapped host:
  `(?<![\w.-])<host>(?![\w-]|\.\w)`. Longest-first order is no longer needed: an anchored host
  never matches inside another.

## Library check (FR-006)

Before the change, every steerable library vector (no `harmful_task`, no `protocol_filter`,
single turn, in a family category) was rendered with the current code and tested with the
wider path check. Newly skipped: 0 of 81 steerable at standard coverage (595 candidates), 0 of
91 at comprehensive (669 candidates); the library holds 677 vectors. Re-run after fix round 1
(Windows paths): still 0. Two raw library prompts name a path (`pe_capability_expansion`,
`pe_sudo_equivalent`), and the existing word check or the resource fill already handles both.

## Constitution Check

Strict mypy, ruff and the touched tests; test first (red run before the change).

## Test plan

`test_chain_targeting.py`: the flat inbox agent's trifecta target (1 to 5 vectors, legs named,
mailbox named, no shared id); ends from the evidence for both trifecta types; the shared pool;
five credential paths through `_resource` and `_render`; path look-alikes pass; whole-host swap
of indicators and description. The `CHOSEN` pins for the six-tool agent gain the trifecta's five
picks, each prompt read by hand. `test_tool_aliases.py`: `Read(/etc/shadow)`.
