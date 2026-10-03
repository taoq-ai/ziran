# Implementation Plan: CI finding suppression baseline and regression gate (accept / suppress / regress)

**Branch**: `046-ci-suppression-baseline` | **Date**: 2026-10-03 | **Spec**: [spec.md](spec.md)
**Issue**: #395 | **Base**: `origin/develop` @ 7d4132e.
**Siblings (parallel)**: #447 / spec 045, #399 / spec 047, #217 / spec 048. Shared file:
`ziran/interfaces/cli/main.py` (#399 edits `scan` and `_display_results`; this spec edits only the
`ci` command and `_display_gate_result`).

## Summary
`ziran ci` loads an optional committed acceptance record, `.ziran/suppressions.yaml` (or
`--suppressions PATH`). Each finding the gate already counts (successful attack results and
dangerous tool chains) gets a stable **fingerprint** (identity) and a **content hash** (material
content). A finding whose fingerprint and content hash match a non-expired entry is `suppressed`;
fingerprint matches but content hash does not -> `regressed`; anything else -> `new`. Thresholds
count new + regressed only; regressions and expired entries add violations naming the fingerprint;
`policy_violation` is recomputed so a fully suppressed run can pass. SARIF marks suppressed results
with `suppressions[]`, GitHub annotations and the step-summary table skip them, and the CLI prints
the three counts and the fingerprint/hash of every unsuppressed finding. Without a file, nothing
changes (byte-identical outputs).

## Technical Context
**Language/Version**: Python 3.11+ (CI matrix 3.11, 3.12, 3.13)
**Primary Dependencies**: Pydantic v2 (suppression file + finding models), PyYAML `safe_load`, stdlib `hashlib`/`json`/`datetime`, Click. No new dependencies.
**Storage**: one user-committed YAML file, read only by `ziran ci`.
**Testing**: pytest `@pytest.mark.unit`; hand-built `CampaignResult` / `PhaseResult` (the
`_make_campaign` / `_make_attack` / `_make_chain` pattern of `tests/unit/test_cicd.py`, copied
locally, not imported from another test module), Click `CliRunner` with `monkeypatch.chdir(tmp_path)`.
No network, no LLM.
**Target Platform**: `ziran ci` CLI and the `ziran.application.cicd` API.
**Project Type**: single Python package.
**Constraints**: mypy strict, line length 100; absent file -> byte-identical outputs; hexagonal
layering (fingerprints in the domain, loading/classification in application, flag in interfaces).
**Facts checked on 7d4132e** (scratch commands, not committed):
- `yaml.safe_load("expires: 2026-12-31")` -> `{'expires': datetime.date(2026, 12, 31)}`.
- `AttackKnowledgeGraph().add_chain_finding(DangerousChain(tools=["read_file", "http_request"],
  risk_level="critical", vulnerability_type="data_exfiltration", exploit_description="x"))` returns
  `composition::data_exfiltration::read_file->http_request`.
- `findings_extractor._compute_fingerprint("test_agent", "v1", "prompt_injection")` ==
  `a8fe72c13edad12d1df1d032a83ebe7a5b0320e125cfc28de5321a0421117f6e`.
- `CampaignResult.success` (set in `agent_scanner/result_builder.py`) is
  `critical_paths or any phase vulnerabilities_found or critical_chain_count > 0`; critical paths
  end at `VULNERABILITY` nodes (attack `vector_id`s, `composition::...` chain nodes) or
  `DATA_SOURCE` nodes (`sensitive_data`, added for every dangerous capability in `scanner.py`).
  Today `gate.py` fails `policy_violation` whenever `result.success` is true, so suppression alone
  could never pass the default gate; FR-008 recomputes it.
- Callers: `QualityGate`, `write_sarif`, `emit_annotations`, `write_step_summary`, `set_output` are
  only called from the `ci` command in `main.py` (and tests). `QualityGate._count_findings(result)`
  is called by `tests/unit/test_cicd.py` (signature must stay). `_compute_fingerprint` is imported
  by `tests/unit/test_findings_extractor.py` (name must stay importable).

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Hexagonal | PASS | Pure fingerprint/hash functions and the file/finding models live in `ziran/domain/entities/ci.py` (stdlib + pydantic only). YAML loading and classification live in `ziran/application/cicd/gate.py`, beside the existing `from_yaml`. The CLI flag and file resolution live in `ziran/interfaces/cli/main.py`. The web `findings_extractor` (interfaces) imports the moved domain function. No outer layer imported inward. |
| II. Type safety | PASS | `SuppressionEntry`, `SuppressionFile`, `GateFinding` are Pydantic; `extra="forbid"` on the committed file (trust boundary); `Literal` kind/state; every function annotated. |
| III. Tests | PASS | Test-first; new `tests/unit/test_cicd_suppressions.py` covers suppress / regress / expire / new / absent / all-suppressed-default-passes, SARIF, GHA and CLI. Existing tests unmodified (regression net for "absent = unchanged"). |
| IV. Async-first | PASS (N/A) | `ziran ci` is a sync CLI entry point reading two small local files, like today's gate config load. |
| V. Extensibility | PASS | No new port or adapter. |
| VI. Simplicity | PASS | No new module: models in the existing `ci.py`, loader + classification in the existing `gate.py`. Reuses the web fingerprint (moved, not copied), `yaml.safe_load`, `_sarif_document`/`_build_result`, `set_output`. One `GateResult.suppressed_attacks()` helper replaces three copies of the same lookup. No generator, no stale-entry report, no critical-path fingerprints. |

No violations; Complexity Tracking not needed.

## Public contract

Binding for the #395 implementer. Names, signatures, field names, rule names, YAML keys, output
names and printed formats MUST NOT change without updating this file.

### 1. `ziran/domain/entities/ci.py` (edit: append; existing models unchanged except `GateResult`)

```python
import hashlib
import json
from collections.abc import Sequence
from datetime import date
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

FindingKind = Literal["attack", "chain"]
SuppressionState = Literal["new", "suppressed", "regressed"]

_Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_NonBlank = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _canonical(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def attack_fingerprint(target_agent: str, vector_id: str, category: str) -> str:
    """Identity of a successful attack result (moved from web findings_extractor)."""
    return _sha256(f"{target_agent}:{vector_id}:{category}")


def chain_fingerprint(target_agent: str, vulnerability_type: str) -> str:
    """Identity of a dangerous tool chain. The tools are deliberately NOT part of the key."""
    return _sha256(f"chain:{target_agent}:{vulnerability_type}")


def attack_content_hash(severity: str, category: str) -> str:
    return _sha256(_canonical({"category": category, "severity": severity}))


def chain_content_hash(tools: Sequence[str], risk_level: str) -> str:
    return _sha256(_canonical({"risk_level": risk_level, "tools": list(tools)}))


class SuppressionEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fingerprint: _Hex64
    content_hash: _Hex64
    reason: _NonBlank
    added_by: _NonBlank
    expires: date | None = None  # valid through this date; expired when expires < today

    def expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today


class SuppressionFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    entries: list[SuppressionEntry] = Field(default_factory=list)


class GateFinding(BaseModel):
    """One finding the gate counts, with its suppression classification."""

    kind: FindingKind
    index: int          # position in CampaignResult.attack_results / .dangerous_tool_chains
    label: str          # vector_id (attack) or vulnerability_type (chain)
    severity: str       # raw value; only low|medium|high|critical are counted
    fingerprint: str
    content_hash: str
    state: SuppressionState = "new"
    reason: str = ""    # reason of the matching entry when state == "suppressed"
```

`GateResult` gains (appended after `summary`; existing fields and properties unchanged):

```python
    findings: list[GateFinding] = Field(default_factory=list)
    new_findings: int = 0
    suppressed_findings: int = 0
    regressed_findings: int = 0
    suppressions_applied: bool = False

    def suppressed_attacks(self) -> dict[int, str]:
        """attack_results index -> entry reason, for every suppressed attack result."""
        return {f.index: f.reason for f in self.findings
                if f.kind == "attack" and f.state == "suppressed"}
```

Hash inputs: the content-hash payload keys differ per kind (`category`/`severity` vs
`risk_level`/`tools`), so an attack hash can never equal a chain hash. Tools keep their recorded
order (a chain is a sequence). Nothing from `evidence`, responses, prompts, names or descriptions
is hashed. A fingerprint collision across kinds (e.g. an agent literally named `chain`) can only
yield `regressed`, never `suppressed`, because the content hashes differ: fail-closed.

### 2. `ziran/interfaces/web/services/findings_extractor.py` (edit: 2 lines)
Delete the local `_compute_fingerprint` and the now-unused `import hashlib`; add
`from ziran.domain.entities.ci import attack_fingerprint as _compute_fingerprint`. Call site and
`tests/unit/test_findings_extractor.py` unchanged.

### 3. `ziran/application/cicd/gate.py` (edit)

```python
def load_suppressions(path: Path) -> SuppressionFile:
    """Read and validate a suppressions YAML file.

    Raises FileNotFoundError (missing), ValueError (not a mapping, or pydantic
    ValidationError, which subclasses ValueError), yaml.YAMLError (bad YAML).
    """
```
Not-a-mapping message: `f"Invalid suppressions file — expected mapping, got {type(data).__name__}"`
(same shape as `from_yaml`).

```python
class QualityGate:
    def evaluate(
        self,
        result: CampaignResult,
        suppressions: SuppressionFile | None = None,
        *,
        today: date | None = None,     # default date.today(); tests inject
    ) -> GateResult: ...

    @staticmethod
    def _count_findings(result: CampaignResult) -> FindingCount:  # signature kept (tests call it)
        return QualityGate._tally(QualityGate._findings(result))

    @staticmethod
    def _findings(result: CampaignResult) -> list[GateFinding]: ...   # all state="new"

    @staticmethod
    def _tally(findings: list[GateFinding]) -> FindingCount: ...      # non-suppressed only

    @staticmethod
    def _classify(
        findings: list[GateFinding], suppressions: SuppressionFile, today: date
    ) -> tuple[list[GateFinding], list[SuppressionEntry]]: ...        # (classified, expired)
```

`_findings` (one per counted finding, attack results first in list order, then chains):
- attack result `ar` (same `raw if isinstance(raw, dict) else raw.model_dump()` idiom) with
  `ar.get("successful")` truthy: `vector_id = str(ar.get("vector_id", ""))`,
  `category = str(ar.get("category", "unknown"))`, `severity = str(ar.get("severity", "medium"))`
  (the web extractor's `vector_id`/`category` defaults; today's gate severity default);
  `fingerprint = attack_fingerprint(result.target_agent, vector_id, category)`,
  `content_hash = attack_content_hash(severity, category)`, `label = vector_id`, `index` = position
  in `result.attack_results`.
- chain `c` in `result.dangerous_tool_chains`: `vt = str(c.get("vulnerability_type", "unknown"))`,
  `tools = [str(t) for t in c.get("tools", [])]`, `severity = str(c.get("risk_level", "medium"))`;
  `fingerprint = chain_fingerprint(result.target_agent, vt)`,
  `content_hash = chain_content_hash(tools, severity)`, `label = vt`.
- `_tally` counts `state != "suppressed"` findings whose `severity` is one of the four levels.
  For a result with no file this is exactly today's `_count_findings` (same defaults, same
  inclusion rules; the dead `isinstance(chain, dict)` branch goes: the field is `list[dict]`).

`_classify` rules (entries considered in file order):
1. `active = [e for e in entries if not e.expired(today)]`, `expired = [e for e in entries if
   e.expired(today)]`.
2. For each finding: if some `e in active` has `e.fingerprint == f.fingerprint and
   e.content_hash == f.content_hash` -> `state="suppressed"`, `reason=e.reason` (first match);
   elif some `e in active` has `e.fingerprint == f.fingerprint` -> `state="regressed"`;
   else `state="new"`. Use `model_copy(update=...)`; do not mutate.

`evaluate` order (checks 1-3 are today's code, fed by `counts = self._tally(findings)`):
1. trust score; 2. `max_critical_findings`; 3. per-severity thresholds (unchanged code);
4. `policy_violation` when `self.config.fail_on_policy_violation`:
   - `suppressions is None`: today's check verbatim (`result.success` -> rule `policy_violation`,
     message `"Critical attack paths or tool-composition chains were found"`, severity
     `critical`). The no-op `pass` branch above it may be deleted.
   - else: `backed` = `{f.label for suppressed attack findings} | {_composition_node_id(
     result.dangerous_tool_chains[f.index]) for suppressed chain findings}`;
     `unsuppressed = count(state != "suppressed")`;
     `paths = count(p for p in result.critical_paths if not p or p[-1] not in backed)`;
     `vulns = len({v for ph in result.phases_executed for v in ph.vulnerabilities_found} - backed)`;
     if any of the three > 0 -> `GateViolation(rule="policy_violation", message=f"Unsuppressed
     findings or unbacked critical paths were found ({unsuppressed} unsuppressed finding(s),
     {paths} unbacked critical path(s), {vulns} unbacked phase vulnerability(ies))",
     severity="critical")`.
5. one violation per regressed finding, in finding order: `GateViolation(rule=
   "suppression_regressed", message=f"Suppressed finding {f.fingerprint} changed: content hash is
   now {f.content_hash}; review it and update the entry", severity="high")`.
6. one violation per expired entry, in file order: `GateViolation(rule="suppression_expired",
   message=f"Suppression {e.fingerprint} expired on {e.expires.isoformat()} (reason: {e.reason});
   renew or remove the entry", severity="high")`.

```python
def _composition_node_id(chain: dict[str, Any]) -> str:
    # Mirrors AttackKnowledgeGraph.add_chain_finding; pinned by a drift test.
    tools = [str(t) for t in chain.get("tools", [])]
    return f"composition::{chain.get('vulnerability_type', 'unknown')}::{'->'.join(tools)}"
```

`GateResult` construction: `findings` (classified, or all `new` without a file), the three counts
from `findings`, `suppressions_applied = suppressions is not None`. `summary` is today's
`_build_summary(...)` string; when `suppressions_applied`, append
`f" | Suppressions: new {n}, suppressed {s}, regressed {r}"`.

### 4. `ziran/application/cicd/sarif.py` (edit)

```python
def generate_sarif(result: CampaignResult, gate: GateResult | None = None) -> dict[str, Any]
def write_sarif(result: CampaignResult, path: Path, gate: GateResult | None = None) -> Path
```
`skip = gate.suppressed_attacks() if gate else {}`; iterate `enumerate(result.attack_results)`;
for an index in `skip`, after `_build_result`, set
`sarif_result["suppressions"] = [{"kind": "external", "justification": skip[i]}]`. Rules,
levels, message and properties unchanged. `generate_audit_sarif` untouched. `GateResult` imported
under `TYPE_CHECKING`.

### 5. `ziran/application/cicd/github_actions.py` (edit)

```python
def emit_annotations(result: Any, gate: GateResult | None = None) -> list[str]
def write_step_summary(gate: GateResult, result: Any, *, summary_path: str | None = None) -> str  # unchanged
```
- `emit_annotations`: skip indices in `gate.suppressed_attacks()` (when `gate` given).
- `write_step_summary`: the "Vulnerabilities Found" list skips `gate.suppressed_attacks()`
  indices (cap of 20 and "... and N more" applied after filtering). When `gate.suppressions_applied`,
  insert after the Finding Summary table (after its trailing blank line):
  ```
  ### Suppressions

  | State | Count |
  |-------|-------|
  | New | {n} |
  | Suppressed | {s} |
  | Regressed | {r} |

  ```
  Without a file, output is unchanged.

### 6. `ziran/interfaces/cli/main.py` — `ci` command and `_display_gate_result` only

New option (after `--sarif`), parameter `suppressions_path: str | None` placed after
`sarif_path` and before `*`:
```python
@click.option(
    "--suppressions",
    "suppressions_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Suppressions YAML of accepted findings (default: .ziran/suppressions.yaml if present).",
)
```
Between step 2 (gate) and step 3 (evaluate):
```python
sup_path = Path(suppressions_path or ".ziran/suppressions.yaml")
suppressions = None
if suppressions_path or sup_path.is_file():
    try:
        suppressions = load_suppressions(sup_path)
    except Exception as e:
        console.print(f"[bold red]Error loading suppressions:[/bold red] {e}")
        sys.exit(1)
```
Then `gate.evaluate(result, suppressions)`, `write_sarif(result, Path(sarif_path), gate_result)`,
`emit_annotations(result, gate_result)`, and after the four existing `set_output` calls:
```python
if gate_result.suppressions_applied:
    set_output("new_findings", str(gate_result.new_findings))
    set_output("suppressed_findings", str(gate_result.suppressed_findings))
    set_output("regressed_findings", str(gate_result.regressed_findings))
```
Docstring: add `ziran ci results.json --suppressions .ziran/suppressions.yaml` to Examples.

`_display_gate_result`, only when `gate.suppressions_applied`:
- panel text gets `f"  |  New: {n}  Suppressed: {s}  Regressed: {r}"` appended;
- after the violations table and before the dim summary, if any finding is not suppressed:
  `console.print("Unsuppressed findings (copy fingerprint/content_hash into the suppressions file to accept):")`
  then one line per finding with `state != "suppressed"`, printed with
  `console.print(line, markup=False, highlight=False, soft_wrap=True)` (no wrapping, so hashes copy
  intact), where
  `line = f"  {f.state} {f.kind} {f.label} [{f.severity}] fingerprint={f.fingerprint} content_hash={f.content_hash}"`.

### 7. Suppressions file format (`.ziran/suppressions.yaml`)

```yaml
version: 1
entries:
  - fingerprint: 3f1c...64 lowercase hex   # printed by `ziran ci`
    content_hash: 9ab0...64 lowercase hex  # printed by `ziran ci`
    reason: "Prompt-injection echo accepted: output is sandboxed (SEC-123)"
    added_by: "security-team"
    expires: 2026-12-31                    # optional; valid through this date
```

### 8. Outputs (only when a suppressions file is loaded)

| Surface | Addition |
|---|---|
| `GateResult` | `findings`, `new_findings`, `suppressed_findings`, `regressed_findings`, `suppressions_applied=True` |
| `GateResult.summary` | `... | Suppressions: new N, suppressed S, regressed R` |
| `$GITHUB_OUTPUT` | `new_findings=N`, `suppressed_findings=S`, `regressed_findings=R` |
| Step summary | `### Suppressions` table; suppressed rows dropped from "Vulnerabilities Found" |
| Annotations | none for suppressed attack results |
| SARIF | `suppressions: [{kind: external, justification: <reason>}]` on suppressed results |
| Console | panel counts + one line per unsuppressed finding with fingerprint and content hash |
| Violations | `suppression_regressed`, `suppression_expired` (+ recomputed `policy_violation`) |

`finding_counts`, `total_findings`, `critical_findings` exclude suppressed findings.

### 9. Docs
- `docs/guides/cicd-integration.md`: new `## Suppressing Accepted Findings` after `### Exit Codes`
  (before `## Policy Engine`): file format (§7), auto-load / `--suppressions`, how fingerprint vs
  content hash behave (table: what changes -> new / regressed / still suppressed), expiry, the
  FR-008 policy rule and the `DATA_SOURCE` limitation with the `fail_on_policy_violation: false`
  workaround, bootstrap (`version: 1` + `entries: []`, run, copy printed lines), SARIF/annotation
  behaviour, the three outputs (note: the composite action does not re-export them yet). Any
  sample console output pasted must come from a real `ziran ci` run on a fixture.
- `docs/reference/cli.md`, `ziran ci` options table: row
  `| --suppressions | .ziran/suppressions.yaml if present | Accepted-findings file; see CI/CD guide |`.

## Acceptance criteria -> offline proof

| Criterion (issue, as narrowed) | Proven by | Live? |
|---|---|---|
| A listed finding does not fail the gate; summary reports it as suppressed | `TestGateSuppressions::test_suppressed_attack_*`, `test_suppressed_chain_*` (US1.1-1.2): counts, no threshold violation, summary substring | No |
| All findings suppressed with the default config passes | `test_all_suppressed_default_config_passes` (US1.3): attack + chain + critical paths ending at `v1` and the composition node + phase `vulnerabilities_found=["v1"]` + `success=True` -> `passed`, exit 0; `test_unbacked_data_source_path_fails` (edge); `test_composition_node_id_matches_graph` (drift guard via `AttackKnowledgeGraph.add_chain_finding`) | No |
| Changing the tool chain flips to regressed and fails | `test_chain_tools_change_regresses` (US2.1) + severity/risk changes (US2.2-2.3); `suppression_regressed` message contains the fingerprint | No |
| Cosmetic / LLM-flapping changes stay suppressed | `test_evidence_and_text_changes_stay_suppressed` (US2.4, includes `evidence["tool_calls"]`) | No |
| Expired entry fails with a clear message | `test_expired_entry_*` (US3.1-3.2) with injected `today`; message contains fingerprint and date | No |
| New findings still fail | `test_new_finding_fails` (US4.1); CLI `test_ci_prints_fingerprints` (US4.2) | No |
| Absent file = byte-identical | existing suites unmodified (`test_cicd.py`, `test_cli_main.py::TestCiCommand`, `test_findings_extractor.py`); `TestAbsent` (no new output lines, `$GITHUB_OUTPUT` has exactly the 4 old lines, no `suppressions` key in SARIF); SC-003 golden diff: outputs captured on `origin/develop` before the change vs after (tasks T001/T020) | No |
| SARIF `suppressions` field | `TestSarifSuppressions` (US6.1) | No |
| Annotations / step summary skip suppressed; counts surfaced | `TestGitHubActionsSuppressions` (US6.2), CLI `$GITHUB_OUTPUT` test (US6.3) | No |
| File auto-load / override / errors | `TestCiCommandSuppressions` (US7.1-7.4) with `monkeypatch.chdir(tmp_path)` | No |
| Fingerprint matches the web findings page | `test_attack_fingerprint_pinned`: `attack_fingerprint("test_agent", "v1", "prompt_injection") == "a8fe72c1...17f6e"` (value computed from today's `_compute_fingerprint`) and `is` the function imported by `findings_extractor` | No |
| Unit tests cover suppress / regress / expire / new | all of the above in `tests/unit/test_cicd_suppressions.py` | No |
| Documented in the CI/CD guide | §9 docs; reviewed in the PR | No |

Nothing in this feature needs a live model or network.

## Project Structure

### Documentation (this feature)
```text
specs/046-ci-suppression-baseline/
├── spec.md
├── plan.md
└── tasks.md
```

### Source Code (repository root)
```text
ziran/domain/entities/ci.py                         # edit: fingerprint/hash fns, SuppressionEntry, SuppressionFile, GateFinding, GateResult fields + suppressed_attacks()
ziran/interfaces/web/services/findings_extractor.py # edit: import attack_fingerprint as _compute_fingerprint
ziran/application/cicd/gate.py                      # edit: load_suppressions, evaluate(suppressions, today), _findings/_tally/_classify, _composition_node_id
ziran/application/cicd/sarif.py                     # edit: gate kwarg, suppressions[] on suppressed results
ziran/application/cicd/github_actions.py            # edit: emit_annotations gate kwarg, step-summary filtering + table
ziran/interfaces/cli/main.py                        # edit: ci --suppressions, loading, outputs; _display_gate_result
docs/guides/cicd-integration.md                     # edit: "Suppressing Accepted Findings"
docs/reference/cli.md                               # edit: --suppressions row
tests/unit/test_cicd_suppressions.py                # new
```
**Structure Decision**: no new source module; every change sits next to the code it extends.
`scanner.py` (750-line cap) and `attack_executor.py` are not touched.

## Release note for the implementer
Commit as `feat(cicd): finding suppression baseline and regression gate` (tests may be a separate
`test(cicd): ...`, docs `docs(cicd): ...`). No `!`, no `BREAKING CHANGE` (new optional file and
flag; absent file is byte-identical). No `Co-Authored-By`. PR targets `develop`, links #395 and
states the SC-003 golden diff result verbatim. Keep `main.py` edits inside `ci` and
`_display_gate_result` (#399 edits `scan` / `_display_results` in parallel).

## Phases
- P0: capture golden `ziran ci` outputs on `origin/develop` (SC-003).
- P1 (tests first): domain fingerprints, hashes, file models, `GateResult` fields; move the web
  fingerprint (FR-001..FR-004).
- P2 (tests first): `load_suppressions`, classification, counts, violations, policy rule
  (FR-005..FR-008).
- P3 (tests first): SARIF and GitHub Actions (FR-010, FR-011).
- P4 (tests first): CLI flag, auto-load, outputs, printed lines (FR-009, FR-012).
- P5: golden diff (FR-013), docs (FR-014), gates: `uv run ruff check .`, `uv run ruff format
  --check .`, `uv run mypy ziran/`, `uv run pytest --cov=ziran` (>= 85%). Do not commit `uv.lock`
  drift.

## Complexity Tracking
None.
