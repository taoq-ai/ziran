# Feature Specification: external benchmark harness for the response detectors

**Feature Branch**: `feat/062-ext-eval-harness`
**Created**: 2026-10-29
**Status**: Active
**Base**: `develop` @ 8943b83
**Input**: plan item EXT-EVAL-HARNESS (ziran-paper goal G-9). It implements the external
detection evaluation protocol, `prereg/ext-eval-protocol.md` in taoq-ai/ziran-paper, as drafted
in PR #61 at head `cbf25bd72e5e7bf73ac373341585b15d3bf90c08`. That protocol is under owner
review; this harness is built against that head and must be re-checked if the merged text
differs.

## The item in my own words

ziran's response detectors have only ever been scored on a synthetic dataset that ziran wrote
itself. The protocol fixes how they are scored instead on four published benchmarks
(AgentDojo, InjecAgent, JailbreakBench, HarmBench), each against its own labels. This item
builds the harness that does that scoring. It runs nothing against any benchmark: it is tested
on hand-made fixtures in each benchmark's file format, and the real run (RUN-EXT-EVAL) comes
later, after the intake addendum freezes the harness commit.

The harness must:

- (a) run from its own frozen commit. For each ziran pin (study-v1, study-v0) it exports the
  pinned tree with `git archive` into a fresh folder and starts a fresh process with that folder
  first on `sys.path`. The run fails if any loaded `ziran` module resolves outside the export.
- (b) build `DetectorPipeline(detector_config=DetectorConfig())` with no LLM client, no
  embedder and no `.ziran/detectors.yaml`; call `evaluate` with `vector=None` and an
  `AttackPrompt` with empty indicator lists; and write three verdicts per unit: `refusal`
  (refusal score at least `hit`), `side_effect` (side-effect score at least `hit`) and
  `pipeline` (`DetectionVerdict.successful`).
- (c) map each benchmark's records to `prompt`, `response.content` and `response.tool_calls` as
  protocol section 4 says. For AgentDojo this includes the post-injection row, cut after the
  first `tool` message whose text contains `<INFORMATION>`, with a count of logs that have no
  such message. For InjecAgent it uses a reviewed copy of `evaluate_output_prompted` (nltk
  replaced by a standard-library `ngrams`, both `print` calls dropped, source sha256 recorded),
  skips `Action` values `None` and `N/A`, and excludes `invalid` and `parse_error` units.
- (d) run the section 9 intake: a sha256 of every input file before it is parsed, checked
  against the manifest and the section 1 hashes; `results.zip` read in memory under the stated
  limits; the SPDX id of each licence recorded. It records the `DetectorThresholds()` and
  `DetectorConfig()` defaults and the sha256 of the seven pinned files and of `uv.lock` at each
  pin, and the harness commit with the sha256 of each harness file and of its `uv.lock`.
- (e) run under `python -I` (not `-O`), with sockets blocked and every key or token removed from
  the environment, with downloads only outside the repository or under a git-ignored path (a
  test checks this with `git check-ignore`), and write only counts, hashes, unit ids, labels
  and verdicts.
- (f) report X1 to X4 (sensitivity, specificity, precision, prevalence) as k, n, estimate and a
  Wilson 95% interval with z = 1.959964, undefined at n = 0, plus a cluster bootstrap of each
  primary row (2,000 resamples, seed 20261009).
- (g) be tested on hand-made fixtures only, one per benchmark format.

Acceptance, from the item:

1. Given a hand-made AgentDojo-format fixture, when the harness runs, each row carries the
   detector verdict and the benchmark label, and the post-injection row cuts at
   `<INFORMATION>`.
2. Given a zip member with `..` in its path, when intake reads it, the benchmark fails intake
   and is reported as not evaluated (protocol section 10).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Score a benchmark against its own labels (Priority: P1)

The run operator points the harness at one benchmark's intake folder, its manifest and the two
ziran pins. The harness writes one row per unit, row variant and pin, and a summary.

**Independent Test**: the AgentDojo fixture through the full CLI, against an export of the
current commit.

**Acceptance Scenarios**:

1. Each row carries the unit id, the benchmark label (or the exclusion reason) and the three
   verdicts. No row carries response text, detector reasoning or matched indicators.
2. The post-injection row of a log takes only assistant messages after the first tool message
   that contains `<INFORMATION>`; a log with none gives empty content and no calls, and the
   summary counts it.
3. A log whose `error` is not null is excluded as `error`.

### User Story 2 - Refuse a benchmark that fails intake (Priority: P1)

**Acceptance Scenarios**:

1. A zip member whose name contains `..`, starts with `/` or a drive letter, or is a symlink
   fails the archive; the benchmark is reported `not_evaluated` with the reason, and no unit is
   scored.
2. A file whose sha256 differs from the manifest or from protocol section 1 fails intake before
   it is parsed.
3. A licence that is not recognised, or an InjecAgent `results.zip` with no terms file, fails
   intake.
4. A required field missing on any unit fails intake.
5. A JailbreakBench `target_response` equal to its behaviour's `Target` fails intake.

### User Story 3 - Isolated, reproducible pins (Priority: P1)

**Acceptance Scenarios**:

1. The harness refuses to start without `python -I` or with `-O`.
2. A socket connect inside the run raises.
3. The worker's environment holds no variable beyond a fixed allow-list; the parent removes
   every variable whose name looks like a key or token, and reports only how many.
4. A `ziran` module that loads from outside the export fails the run.
5. An input or output path inside the repository that is not git-ignored is refused.

### User Story 4 - Metrics (Priority: P1)

**Acceptance Scenarios**:

1. Wilson intervals match known values; a zero denominator gives `undefined` with no estimate.
2. The cluster bootstrap with seed 20261009 is deterministic and resamples whole clusters.

### Edge Cases

- AgentDojo message content can be a string, a list of blocks or null; only `text` blocks count.
- InjecAgent outputs can be null or too short; the evaluator marks them `invalid`, and they are
  counted per `invalid_reason`.
- The evaluator's `output_parser` signals a malformed output with `assert`, which is why the
  harness refuses `-O`; an exception there makes the unit a `parse_error`.
- HarmBench items whose `model` is `.json` form the `unnamed` cell.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: a package `benchmarks/external_eval/` with a CLI `run.py`, a stand-alone worker
  `worker.py` that imports only the standard library and the pinned ziran, and modules for
  intake, mapping, the InjecAgent evaluator copy and metrics.
- **FR-002**: the worker runs once per pin and benchmark, as `python -I worker.py <export>`,
  reads units as JSON lines on stdin and writes verdicts as JSON lines on stdout; its stderr is
  captured and never printed.
- **FR-003**: inputs are listed in a manifest (relative path to sha256, the licence file, and
  for InjecAgent a terms file); every file is hashed and checked before it is parsed.
- **FR-004**: the section 1 hashes (JailbreakBench `judge-comparison.csv`, HarmBench
  `text_behaviors_val_set.json`, InjecAgent `output_parsing.py`) are constants in the harness.
- **FR-005**: outputs are JSON lines of unit rows plus a JSON summary, both holding only counts,
  hashes, unit ids, model, suite and case ids, labels and verdicts.
- **FR-006**: no change under `ziran/`, and no new dependency.
- **FR-007**: the summary counts, per predictor, the units whose verdict differs between the
  first pin and each other pin (protocol section 4: a difference with matching hashes is
  reported and explained).
- **FR-008**: data and output folders sit apart from the harness folder; the default download
  folder is `downloads/external-eval/` at the repository root, git-ignored.

### Assumptions

- **Layout of `results.zip`.** The archive was never opened. The harness admits members named
  `.../prompted_<model>_InjecAgent/test_cases_<dh|ds>_<base|enhanced>.json`, read as JSON lines,
  the layout InjecAgent's `evaluate_prompted_agent.py` writes. Other members are counted as
  outside the split. Overturn: the archive's listing at intake shows another layout; the harness
  is then fixed before the addendum freezes it.
- **Layout of the HarmBench validation set.** A JSON object from `behavior_id` to a list of
  items. Overturn: the intake field check fails, before any label is read.
- **Licence recognition.** Only the MIT text is recognised (all four repositories state MIT);
  any other text fails intake and goes to section 10, where the owner decides. Overturn: a pin
  ships another research-use licence.
- **The InjecAgent evaluator source was read.** The copy needs the pinned
  `src/output_parsing.py` (code, not data); it was fetched once at the pin and its sha256 matched
  section 1. No InjecAgent data file was read. [evaluator-diff.md](evaluator-diff.md) records
  every difference between the copy and the source.
- **One worker process per pin and benchmark.** The protocol asks for a fresh process per pin;
  a fresh one per benchmark as well keeps each benchmark's run independent.
- **Cells.** Per-cell rows group by each cell key on its own (AgentDojo model, suite and suite
  version; InjecAgent model, case type and setting; HarmBench model). Overturn: the run report
  needs crossed cells, which the rows file allows without a harness change.
- **Excluded units are scored.** Their rows carry verdicts next to the exclusion reason;
  metrics use analysed units only. Overturn: none expected.
- **Each pin runs in the harness's environment.** Protocol section 4 runs one frozen harness
  with each pin's export first on `sys.path`, so third-party packages come from the harness's
  `uv.lock` at both pins. Each pin's own `uv.lock` is hashed for the record only. The worker
  reports its Python version and installed-distribution hash per pin.
- **Isolation scope.** The audit hook blocks network calls, new processes and C-library loads in
  the worker, and network calls in the harness process, which itself starts only git and its
  workers. A hook does not reach another process, so `--ziran-repo` must be a full clone: a
  partial clone is refused, because `git archive` there would fetch blobs over the network.
- **Empty split.** A benchmark whose split or analysed units come out at 0 fails intake (protocol
  sections 9 check 4 and 10), so an unexpected layout is reported as not evaluated.
- **Every loaded module is hashed.** Besides the seven pinned files, the worker hashes every
  `ziran` module it loaded, so a verdict difference between pins can be traced to a file.
- **Archive text stays out of messages.** Intake messages name a member by its index, and member
  names are admitted only in a safe character set, since the model cell and unit id come from them.
- **Run environment.** The summary records the sha256 of the sorted installed distributions
  (`name==version`) next to the `uv.lock` hash, so the versions that ran are checkable against
  the lock (arch note 3 on the protocol at 655a222).

## Success Criteria *(mandatory)*

- **SC-001**: the tests for each user story fail before the code exists and pass after.
- **SC-002**: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/` and
  `uv run pytest -m "not integration" --cov=ziran` pass; `mypy --strict` also passes on
  `benchmarks/external_eval/`.
- **SC-003**: no benchmark artifact is downloaded and nothing runs against a benchmark item.

## Clarifications

### Session 2026-10-29

- Q: Where does the harness live? A: `benchmarks/external_eval/`, next to the existing
  detection-accuracy benchmark, outside the `ziran` package so the pinned export is the only
  `ziran` on the worker's path.
- Q: Should the worker import harness modules? A: no. It imports only the standard library and
  the export, so no harness file can shadow or mix with the pinned code.
- Q: Which rows get the cluster bootstrap? A: the primary row of each benchmark (protocol
  section 6), on the whole-trace variant.
