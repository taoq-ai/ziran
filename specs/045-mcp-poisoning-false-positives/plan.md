# Implementation Plan: MCP metadata analyzer false positives (sibling redirects, output-contract imperatives)

**Branch**: `045-mcp-poisoning-false-positives` | **Date**: 2026-10-03 | **Spec**: [spec.md](spec.md)
**Issue**: #447 (release 0.41.0) | **Base**: `origin/develop` @ 7d4132e.
**Parallel siblings**: #395 (spec 046), #399 (spec 047), #217 (spec 048). No shared file: this
feature edits one source module, two test files and one docs page.

## Summary
`MCPMetadataAnalyzer` gains two narrowly scoped downgrades. (1) A `tool_redirect` whose
`call <target> instead` target is exactly the name of another tool in the same
`analyze_capabilities` call is reported as `sibling_redirect` at `medium`, unless the same text
also matches `exfiltration_directive` or `authority_claim`, or any other redirect in that text
is not a sibling. (2) An `imperative_instruction` whose only matches are the weak words `always`,
`never`, `silently` (not followed by a bare imperative verb) is reported at `low`; anything
model-directed stays `high`. The severity type gains `"low"`. `docs/reference/cli.md` documents
the new severities, that `tool_poisoning` exists only on first registration, and the exit-code
effect.

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: stdlib `re`, `dataclasses`; domain `Severity` literal
(`ziran/domain/entities/attack.py`). No new dependency, `uv.lock` unchanged.
**Storage**: N/A.
**Testing**: pytest, `@pytest.mark.unit`; plain capability dicts for the analyzer; the existing
`InMemoryStore` / `StaticFetcher` helpers of `tests/unit/test_registry_watcher.py` for the watcher.
No network, no LLM, no keys.
**Callers traced** (`grep -rn MCPMetadataAnalyzer ziran tests`):
- `ziran/application/registry_watch/watcher_service.py::_metadata_findings` — called by `watch`
  only when `snapshot_store.load(server)` is `None`; passes the raw `tools/list` entries (dicts with
  `name`, `description`, `inputSchema`, no `type`); maps `f.severity` to `DriftFinding.severity`
  (domain `Severity`, already includes `"low"`) and `f.pattern_matched` into `message`.
- `ziran/application/agent_scanner/scanner.py` (~line 574) — `cap.model_dump(mode="json")` of
  `AgentCapability` (`id`, `name`, `type` in `{"tool","skill","data_access",...}`); MCP handler sets
  `id == name == tool name` for tools; findings are only logged and stored on
  `self._mcp_metadata_findings` (no other reader).
- `ziran/interfaces/cli/watch_registry.py` — exit `1` iff any finding has severity `critical` or
  `high` (line ~373); `_SEVERITY_COLORS` already has `low`.
**Constraints**: mypy strict; line length 100; shipped vulnerable example stays
`critical`/`high`; `scanner.py` (750-line cap) and `attack_executor.py` untouched.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | Edit confined to the application module; it imports the domain `Severity` literal (application -> domain). No infrastructure or interface import. |
| II. Type safety | PASS | `Severity` literal for the field and the pattern table; every new helper annotated. `MCPMetadataFinding` stays a frozen dataclass (pre-existing, not a new data structure; converting it is out of scope). |
| III. Tests | PASS | Test-first; unit tests for every acceptance scenario; one watcher test; the integration test for the shipped example runs unmodified. |
| IV. Async-first | N/A | Pure, synchronous text analysis (unchanged). |
| V. Extensibility | PASS | No new port, no vector change. |
| VI. Simplicity | PASS | No sentence splitter (max over sentences == whole field, spec FR-006), no new module, no config knob, no fuzzy matching. One named group in an existing regex, two constants, one small helper per rule. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #447 implementer. Names and behaviour MUST NOT change without updating this file.

### 1. `ziran/application/static_analysis/mcp_metadata_analyzer.py` (edit)

```python
from ziran.domain.entities.attack import Severity  # Literal["low", "medium", "high", "critical"]

@dataclass(frozen=True)
class MCPMetadataFinding:
    tool_id: str
    field: str
    pattern_matched: str   # now also "sibling_redirect"
    snippet: str
    severity: Severity     # was Literal["critical", "high", "medium"]
    recommendation: str

_PATTERNS: dict[str, tuple[re.Pattern[str], Severity, str]]  # same five keys, regexes, severities
```

`tool_redirect` regex: only change is a named group on the first alternative, so the match set is
identical:

```python
r"(?i)(call\s+(?P<target>.{0,20})\s+instead|redirect\s+to|"
r"actually\s+(use|call|invoke)|invoke\s+.{0,20}\s+tool\s+instead|"
r"forward\s+.{0,10}\s+to\s+.{0,20}\s+tool)"
```

New module constants:

```python
_WEAK_IMPERATIVES = frozenset({"always", "never", "silently"})
# A weak word directly followed by one of these bare verbs is model-directed ("always call X").
_IMPERATIVE_VERB = re.compile(
    r"\s+(call|use|invoke|run|execute|send|pass|include|tell|ask|reveal|mention|read|write)\b",
    re.IGNORECASE,
)
_SIBLING_REDIRECT_RECOMMENDATION = (
    "Tool metadata routes the caller to a sibling tool of the same server. "
    "Usually benign routing advice; confirm the named tool is the one intended."
)
```

`MCPMetadataAnalyzer` (public surface unchanged):

```python
def analyze_capabilities(self, capabilities: list[dict[str, Any]]) -> list[MCPMetadataFinding]
```
- Before the loop, build the tool-name set:
  `names = {n for cap in capabilities if cap.get("type", "tool") == "tool"
  and (n := cap.get("id") or cap.get("name"))}` (falsy ids skipped, so `"unknown"` is never a
  name).
- Per capability, `siblings = frozenset(names - {tool_id})`, passed to every `_check_text` call
  of that capability (description and each parameter description).
- Sort map becomes `{"critical": 0, "high": 1, "medium": 2, "low": 3}`.

```python
@staticmethod
def _check_text(
    text: str, tool_id: str, field: str, siblings: frozenset[str]
) -> list[MCPMetadataFinding]
```
Algorithm (one finding per pattern per field, as today):
1. `hits = {name: list(regex.finditer(text)) for name, (regex, _, _) in _PATTERNS.items()}`.
2. For each pattern with hits: `match = hits[name][0]` (same match `regex.search` returned, so the
   snippet rule and snippet text are unchanged); start from the table's `(severity,
   recommendation)` and `pattern_matched = name`.
3. `imperative_instruction`: if every hit is weak (`m.group(0).lower() in _WEAK_IMPERATIVES and
   not _IMPERATIVE_VERB.match(text, m.end())`), severity = `"low"`. Otherwise unchanged `"high"`.
4. `tool_redirect`: if `not hits["exfiltration_directive"] and not hits["authority_claim"]` and
   every hit satisfies `_redirect_target(m) in siblings`, then `pattern_matched =
   "sibling_redirect"`, severity `"medium"`, recommendation `_SIBLING_REDIRECT_RECOMMENDATION`.
   Otherwise unchanged `tool_redirect` / `"critical"`.
5. Snippet extraction exactly as today (30 chars either side of `match`, strip, 200-char cap).

```python
def _redirect_target(match: re.Match[str]) -> str:
    """Target of a ``call <target> instead`` match, or "" for target-less redirect forms."""
    return (match.group("target") or "").strip(" \t`'\"")
```
`""` is never in `siblings`, so target-less forms stay `critical`. Comparison is exact and
case-sensitive.

Output shape: list of `MCPMetadataFinding`, sorted critical -> high -> medium -> low. New values
only: `pattern_matched == "sibling_redirect"` with `severity == "medium"`; `pattern_matched ==
"imperative_instruction"` with `severity == "low"`.

### 2. Callers (no edit)
`watcher_service._metadata_findings` already maps `severity` into `DriftFinding.severity`
(`Severity`, includes `"low"`) and puts `pattern_matched` in `message` as
`"Suspicious tool metadata (sibling_redirect) on server '<s>': <recommendation>"`. The scanner
only logs. `watch_registry`'s exit predicate is unchanged, so the effect is that servers whose
only findings are `sibling_redirect` / low imperatives exit `0`.

### 3. `docs/reference/cli.md` (edit, "First registration" paragraph, ~line 439)
Replace "(severity `critical`, `high` or `medium`)" with `critical`, `high`, `medium` or `low`
and add: a redirect whose `call <tool> instead` target is another tool of the same server is
reported as `sibling_redirect` at `medium` (still `critical` if the same text also carries an
exfiltration or authority pattern, or names any tool outside the server); `always` / `never` /
`silently` used to describe the tool's own output ("never returns an empty list") are `low`,
model-directed imperatives (`you must`, `before calling`, `ignore previous`, `do not tell`,
`always call`, ...) stay `high`. `tool_poisoning` findings are emitted only on first registration,
when no snapshot exists (`previous_value` is always `null`): they are first-measurement
information, not drift. Exit codes count only `high`/`critical`, so a server whose only findings
are sibling redirects and output-contract imperatives exits `0`. Exit-code table unchanged.

## Acceptance criteria -> offline proof

| Criterion (issue as narrowed by the scope brief) | Proven by | Live model? |
|---|---|---|
| Sibling redirect -> `sibling_redirect` / `medium` | `test_mcp_metadata_analyzer.py::TestSiblingRedirect` US1.1 (plus backtick-quoted target) | No |
| Non-sibling redirect stays `critical` (`admin_panel`) | existing `test_tool_redirect_detected` + new assertion of `critical` in `TestSiblingRedirect` US1.2 | No |
| Near-miss target stays `critical` (`get_answer_and_exfil`) | `TestSiblingRedirect` US1.3 | No |
| No downgrade with exfiltration / authority in the same text | US1.4, US1.5 | No |
| No downgrade on loose matches (mixed redirects, self, case, `the X tool`) | US1.6, US1.7, `"call the get_answer tool instead"` | No |
| Output-contract imperatives -> `low` (`never returns an empty list`, `none is silently chosen`) | `TestImperativeSeverity` US2.1 | No |
| Model-directed imperatives stay `high` (incl. `always call`) | US2.2, US2.3, US2.4 | No |
| Severity type and sort accept `low` | `TestImperativeSeverity`: a low and a critical finding sort critical first, low last; `uv run mypy ziran/` | No |
| Watcher: issue server's first registration has no high/critical `tool_poisoning`, `sibling_redirect` in message | `test_registry_watcher.py::TestFirstRegistrationToolPoisoning::test_sibling_redirect_and_output_contract_not_gating` (US3.1) | No |
| Shipped vulnerable example stays `critical`/`high`, exit `1` | `tests/integration/test_claude_code_plugin_example.py` unmodified + US2.5 unit assertion | No |
| Docs: severities, first-registration-only, exit-code effect | `docs/reference/cli.md` diff (review) | No |

## Project Structure

### Documentation (this feature)
```text
specs/045-mcp-poisoning-false-positives/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (repository root)
```text
ziran/application/static_analysis/mcp_metadata_analyzer.py  # edit: Severity import, named group, constants, _redirect_target, _check_text(siblings), sort map
tests/unit/test_mcp_metadata_analyzer.py                    # extend: TestSiblingRedirect, TestImperativeSeverity
tests/unit/test_registry_watcher.py                         # extend: one test in TestFirstRegistrationToolPoisoning
docs/reference/cli.md                                       # edit: First registration paragraph
```
**Structure Decision**: single-module change; no new file outside the spec directory.

## Release note for the implementer
Commit as `fix(static-analysis): downgrade sibling-tool redirects and output-contract imperatives
in MCP metadata analyzer` (tests may be split as `test(static-analysis): ...`, docs as
`docs(cli): ...`). No `!`, no `BREAKING CHANGE` (severity of two benign patterns lowered; field set
unchanged), no `Co-Authored-By`. PR targets `develop`, links #447. Do not hand-edit CHANGELOG.md.

## Phases
- P1 (tests first): severity type + imperative rule (FR-001, FR-005, FR-006).
- P2 (tests first): sibling redirect + guards (FR-002..FR-004).
- P3 (test first): watcher test (US3).
- P4: docs (FR-008).
- Gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/`,
  `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock` drift.

## Complexity Tracking
None.
