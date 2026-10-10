# Feature Specification: static CrewAI project reader for `ziran audit`

**Feature Branch**: `crewai-extractor`
**Created**: 2026-10-10
**Status**: Active
**Base**: `develop` @ b813e4f (v0.42.0).
**Track**: FULL (new reader for untrusted input, new JSON key).
**Builds on**: spec 038 (`ziran audit` over Claude Code agents: `agent_chains`, `StaticFinding.agent`
and `.tools`, the JSON row keys), spec 037 (the parse-issue pattern: problems become value-free
issues, never exceptions).
**Input**: `ziran audit` reads Python files and Claude Code agent definitions. A CrewAI project
declares its agents in `config/agents.yaml`, its tasks in `config/tasks.yaml`, and often passes
tools in `crew.py` (`@agent` and `@task` methods that return `Agent(..., tools=[...])` and
`Task(..., tools=[...])`). Nothing reads these files statically today: the only CrewAI code in ziran
is the runtime adapter, which imports and runs the crew. This feature reads a CrewAI project without
importing or running it, builds each agent's tool set, and runs the same chain construction the
Claude Code audit uses.

## Clarifications

### Session 2026-10-10

Each question is a two-way choice inside the item, answered by the recommended option and recorded
under Assumptions.

- Q: When both the YAML `tools:` key and the crew.py `tools=` argument are set, which wins? A: the
  crew.py argument (CrewAI's `process_config` keeps an explicit value).
- Q: Is a unit's tool set per task or per agent? A: per agent, the union of agent and task tools;
  per-task sets are kept in the output.
- Q: Are tool names resolved through variables and `@tool` methods? A: a variable bound once in
  crew.py by a simple assignment to a call resolves to the callee name; `@tool` methods are not
  resolved. Any other element is kept as its source text.
- Q: Does a unit with an error still get chains? A: yes, over the tools that were read; the error
  is reported next to them.
- Q: Which crew.py belongs to a config directory? A: `crew.py` beside the config directory, then
  inside it. Other file names are not read.
- Q: Does an agents.yaml alone make a project? A: no, tasks.yaml must be beside it.
- Q: What does the sampler draw from? A: units without errors, sorted by `(file, agent)`.

## User Scenarios & Testing *(mandatory)*

### User Story 1: a CrewAI project with a dangerous chain fails the audit (Priority: P1)

A developer runs `ziran audit ./my_crew/ --format json`. An agent whose own tools or whose tasks'
tools combine into a dangerous chain is reported with the agents.yaml file and line, the agent name
and the chain's tools.

**Why this priority**: it is the item's promise.

**Independent Test**: `CliRunner` over a fixture project under `tests/fixtures/crewai/`.

**Acceptance Scenarios**:

1. **Given** a fixture project whose agent `researcher` has `tools=[FileReadTool()]` in its
   `@agent` method and is assigned a task whose `tools:` key in tasks.yaml names
   `send_email`, **When** `ziran audit PATH --format json` runs, **Then** the exit code is 1 and
   `findings` holds a `CR001` row with `"agent": "researcher"`, the agents.yaml path in `file`, the
   line of the `researcher:` key in `line`, and the two tools in `tools`.
2. **Given** the same run, **Then** the document has a `crewai` key listing one unit per
   agents.yaml entry with `agent`, `file`, `line`, `tools` (the union), `agent_tools`, `tasks`
   (each with `name` and `tools`) and `errors`.
3. **Given** a project where no agent has two tools that form a pattern, **Then** there is no
   `CR001` row and the exit code is 0 (text mode) or 0 (json mode, no findings).

### User Story 2: hostile or broken files never crash the audit (Priority: P1)

A security reviewer runs `ziran audit` on third-party repositories. Files can be malformed,
oversized, deeply nested or crafted to run code on import.

**Why this priority**: the input is untrusted; a crash or code execution would be a defect at the
trust boundary.

**Independent Test**: unit tests on the loader with `tmp_path` projects.

**Acceptance Scenarios**:

1. **Given** a crew.py whose module body would write a marker file or raise when imported,
   **When** the project is read, **Then** the marker file does not exist and no exception escapes.
2. **Given** a crew.py with a syntax error, **Then** every agent of that project is still a unit,
   each carrying an error with the crew.py path and the syntax error line, and its tools from
   agents.yaml and tasks.yaml are kept.
3. **Given** a crew.py, agents.yaml or tasks.yaml over 1 MiB, **Then** the file is not parsed and
   an error names the size limit.
4. **Given** a crew.py whose AST is nested deeper than the limit, or a YAML file nested deep
   enough to exhaust the parser's recursion, **Then** the result is an error, not a
   `RecursionError`.
5. **Given** an agents.yaml that is not valid YAML or not a mapping, **Then** the project yields no
   unit and one scan issue for that file.
6. **Given** a `tools=` argument that is not a literal list (`tools=self.get_tools()`), **Then**
   only the unit it belongs to carries an error, and the other units are unaffected.
7. **Given** a file that resolves outside the scanned root through a symlink, **Then** it is not
   read and an error says so.
8. **Given** any error, **Then** its message holds no file content beyond the names of keys and
   methods.

### User Story 3: tool sets follow CrewAI's own rules (Priority: P1)

**Acceptance Scenarios**:

1. **Given** an agents.yaml entry with `tools: [search_tool]` and no `tools=` in crew.py, **Then**
   the agent's tools are `["search_tool"]`.
2. **Given** an `@agent` method with `tools=[SerperDevTool()]` and the entry's `tools:` key also
   set, **Then** the agent's tools are `["SerperDevTool"]` (an explicit argument replaces the YAML
   value, as CrewAI's `process_config` does).
3. **Given** `config=self.agents_config['writer']` in a method named `write_agent`, **Then** the
   method's tools go to the `writer` entry, and a task with `agent: write_agent` (YAML) or
   `agent=self.write_agent()` (crew.py) is assigned to `writer`.
4. **Given** tool elements `SerperDevTool()`, `crewai_tools.FileReadTool(path="x")`,
   `self.my_tool()`, `search` and `self.search`, **Then** the names are `SerperDevTool`,
   `FileReadTool`, `my_tool`, `search` and `self.search`.
5. **Given** a task defined only in crew.py (no tasks.yaml entry) with `agent=self.researcher()`
   and `tools=[X()]`, **Then** `X` is in `researcher`'s task tools.
6. **Given** an agent with no tools anywhere, **Then** its unit has `tools: []` and no chain.
7. **Given** the union, **Then** order is agent tools first, then each task's tools in task order,
   duplicates removed.
8. **Given** `search = SerperDevTool()` and `reader: Any = crewai_tools.FileReadTool(path="x")`
   in crew.py and `tools=[search, reader]`, **Then** the names are `SerperDevTool` and
   `FileReadTool`. A name bound more than once to different callees, or bound to something that
   is not a call, stays as written.
9. **Given** a tool element that is not a call or a name (`*base_tools`, `tools[0]`,
   `self.search`), **Then** it is kept as its source text (`*base_tools`, `tools[0]`,
   `self.search`) and the unit has no error.

### User Story 4: one sample for a hand check (Priority: P2)

A reviewer wants to check by hand that the reader extracts the right tools. They run the sampling
script on a saved `ziran audit --format json` output with a seed.

**Independent Test**: a unit test runs the script on a small JSON document twice with the same seed
and compares the output.

**Acceptance Scenarios**:

1. **Given** an audit JSON with 120 units and `--seed 7 --n 50`, **When** the script runs twice,
   **Then** both runs print the same 50 units, each with its file, agent, agent tools, task tools,
   union and errors.
2. **Given** fewer units than `--n`, **Then** it prints all of them.
3. **Given** units with errors, **Then** they are left out of the sampling frame and the header
   states how many were left out.
4. **Given** a file without a `crewai` key, **Then** the script exits 2 with a message.

### User Story 5: existing audits are unchanged (Priority: P1)

**Acceptance Scenarios**:

1. **Given** a directory without an agents.yaml next to a tasks.yaml, **Then** the JSON document
   has no `crewai` key and rows keep their existing keys. Every existing audit test passes
   unmodified.
2. **Given** a Claude Code agent, **Then** `agent_chains` returns the same chains as before the
   refactor (existing tests in `tests/unit/test_claude_code_audit.py` pass unmodified).

### Edge Cases

- An agents.yaml without a sibling tasks.yaml is not treated as a CrewAI project (other tools use
  that file name).
- A crew.py is looked up next to the config directory (`config/../crew.py`) and then inside it. If
  neither exists, units use the YAML tools only. A config directory given as PATH is the scanned
  root, so `config/../crew.py` lies outside it and is refused (FR-003).
- An agents.yaml entry whose value is not a mapping becomes a unit with an error and no tools.
- `tools:` in YAML must be a list of strings or empty; another value is a unit error.
- A task whose agent cannot be resolved (no `agent` key, or a name that is not a unit) adds tools to
  no unit. A task whose `agent=` argument is not a call, name or attribute, or whose tasks.yaml
  entry is not a mapping, puts an error on every unit of the project, since any of them could be
  its agent.
- Directories in the analyzer's `skip_directories` (`.venv`, `node_modules`, ...) are not walked.
- `@agent` methods without an agents.yaml entry are not units.
- Several projects under one PATH each yield their own units; units are ordered by agents.yaml
  path, then entry order.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Discovery. For PATH as a directory, walk it (no symlinked directories, skipping
  `skip_directories`) and take each directory that holds both `agents.yaml` and `tasks.yaml` as one
  project. For PATH as a file named `agents.yaml`, its directory is the project when `tasks.yaml`
  is beside it.
- **FR-002**: YAML is read with a `yaml.SafeLoader` subclass only. Python is read with
  `ast.parse` only.
  Project code is never imported, executed or evaluated.
- **FR-003**: Each file is read only when its real path lies inside the scanned root and its size
  is at most 1 MiB. The scanned root is PATH's real path for a directory, and the real path of
  the directory above the config directory for an agents.yaml file. A crew.py AST deeper than 200 levels is rejected. A YAML file that holds an
  alias (`*name`) is rejected. `SyntaxError`, `ValueError` (from Python or from YAML, such as an
  impossible date or an integer over Python's digit limit in a value or a key),
  `RecursionError` (from parsing), `RecursionError`, `ValueError` and `MemoryError` from walking
  crew.py (`ast.unparse`), `yaml.YAMLError`, `OSError` and `UnicodeDecodeError` become errors.
- **FR-004**: A unit is one agents.yaml entry. Its `agent_tools` are the names in the `tools=`
  argument of the matching `@agent` method when that argument is present, else the entry's
  `tools:` key. The matching method is the one whose `config=self.agents_config['<key>']` names the
  entry, else the method of the same name.
- **FR-005**: Tasks are the tasks.yaml entries plus `@task` methods whose key is not in tasks.yaml.
  A task's agent is the `agent=` argument of its `@task` method when present, else its `agent:`
  key; a method name is mapped to its entry key as in FR-004. A task's tools follow the same
  precedence as FR-004.
- **FR-006**: A unit's `tools` is the union of its `agent_tools` and the tools of every task
  assigned to it, ordered as in US3.7.
- **FR-007**: A call gives its callee's name (the last attribute of an attribute callee). A name
  bound in crew.py only by simple assignments (`x = F(...)` or `x: T = F(...)`, anywhere in the
  file) that all call the same callee resolves to that callee's name; any other name gives its
  identifier. Any other element, an uncalled attribute such as `self.search` included, is kept as
  its source text (`ast.unparse`), with no error.
  YAML tool names are taken as written. The id is never normalised (see Assumptions, tool id
  form); a test pins case and suffix.
- **FR-008**: Chains for a unit are built by the same construction as `agent_chains` for Claude
  Code: one capability node per tool, an edge for each ordered pair, `analyze(include_cycles=False)`.
  The shared construction is extracted into one function used by both.
- **FR-009**: `ziran audit` appends findings: `CR000` (high) for each scan issue and each unit
  error, `CR001` (the chain's risk level) for each chain, with `agent` and `tools` set. The
  `file` and `line` of `CR001` are the agents.yaml path and the entry's key line.
  A unit with more than 64 tools gets one `CR000` at its agents.yaml entry line and no chains.
- **FR-010**: With `--format json` and a CrewAI project found, rows carry `agent` and `tools` (as
  for Claude Code) and the document gains `crewai`, the list of units (FR-004 to FR-006 fields and
  `errors`, each `{file, line, message}`).
- **FR-011**: A script `scripts/sample_crewai_units.py AUDIT_JSON --seed N [--n 50]` samples units
  without errors with `random.Random(seed)` from the list sorted by `(file, agent)` and prints them.
  It only samples and prints.
- **FR-012**: `docs/reference/cli.md` documents CrewAI detection, the two rules, the `crewai` key
  and the script.

### Assumptions

- Explicit argument over YAML (FR-004, FR-005). Assumed because CrewAI's `process_config` only
  copies a config key when the argument is unset (crewai `utilities/config.py`). Overturn: a reviewer
  wants the union of both sources as an upper bound.
- The union of agent and task tools is the unit's tool set (FR-006). Assumed because CrewAI runs a
  task with `task.tools or agent.tools` and a task's output passes to later tasks as context, so a
  chain can span tasks. It is an upper bound. Per-task sets stay available in `tasks`. Overturn: a
  per-task tool set is wanted as the primary set.
- A variable bound by a simple assignment to a call in crew.py resolves to the callee name, and any
  other element is kept as its source text (FR-007). Assumed because the common CrewAI pattern is
  `search_tool = SerperDevTool()` at module level, and the class name is what chain patterns
  match; keeping odd elements as text lets a hand check judge them instead of dropping them. A name
  bound to two different callees, a tuple unpacking and `@tool` methods are not resolved.
  Overturn: the hand check shows those forms are common.
- An uncalled attribute such as `self.search_tool` is kept as written (FR-007). It is not resolved
  through class-body or `__init__` assignments such as `search_tool = SerperDevTool()`, because
  only a plain variable in `tools=[x]` is resolved; taking the last attribute would give a name
  that is neither the text nor a class. Chains are unchanged, since capability keywords split on
  `.` (a test pins this). Overturn: attribute access is ruled to count as a variable binding.
- Tool id form. A tool id is the tool class or function name exactly as written in agents.yaml,
  tasks.yaml or crew.py (for example `FileReadTool` from `FileReadTool()` or
  `crewai_tools.FileReadTool(...)`, `my_tool` from `self.my_tool()`, `search_tool` from YAML).
  No normalisation: no case change, no suffix stripping, no alias mapping in the reader. Only
  exact duplicates are dropped. Assumed because chain pattern matching and
  `canonical_tool_name` work on this string, so the reader must hand them the id unchanged.
  Overturn: a consumer of the output fixes a different id form.
- A unit with errors still lists the tools that were read and gets its chains. Assumed because a
  partial set is a lower bound and the `errors` list tells a consumer to treat it as such.
  Overturn: a consumer wants errored units to report no chains.
- A unit with more than 64 tools gets `CR000` and no chains (FR-009). Assumed because chain
  construction is quadratic in tools (measured: 6 s at 100 tools, 58 s at 300) and a 1 MiB file
  can name thousands, so one hostile unit could stall the audit. The bound limits chain time
  only, not memory; memory is bounded by the 1 MiB file cap and the alias refusal (FR-003).
  Truncating the set would hide chains, so the unit is reported instead. The `crewai` list still
  carries its full tool set. Overturn: real projects with more than 64 tools on one agent show up
  in the hand check.
- A YAML alias makes its file unusable (FR-003), reported like any other unusable file: an
  agents.yaml becomes a scan issue, a tasks.yaml an error on every unit. Assumed because an alias
  copies its anchored value into every use (a 278 KB tasks.yaml expanded to 64 million tool
  references and 1.7 GB), and CrewAI's generated configs do not use anchors. Merge keys
  (`<<: *x`) are refused too, since they copy the merged pairs and amplify the same way.
  Measured: 0 of 196 sampled real agents.yaml and tasks.yaml files use an alias; a code search
  found 3 agents.yaml files in 2 repositories using merge keys, out of about 10,464 indexed.
  The hand check cannot see refused files, since they yield no units or only errored ones.
  Overturn: more than 1% of the CrewAI config files in a corpus audit's JSON are refused with
  "YAML aliases are not supported".
- The sampling frame leaves out units with errors (FR-011), since those units cannot be
  checked against a complete extraction. Overturn: the reviewer wants errored units sampled too.
- Spec directory `specs/056-crewai-extractor` follows the item name so the workflow hooks find it.

### Key Entities

- **CrewAIAgent**: one unit (name, agents.yaml file and line, agent tools, tasks, errors; `tools`
  is the derived union).
- **CrewAITask**: name and own tools.
- **CrewAIIssue**: file, optional line, message (never file content).
- **CrewAIScan**: root, units, project-level issues, files analysed.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: US1 to US5 acceptance scenarios pass as tests.
- **SC-002**: Every pre-existing test passes unmodified.
- **SC-003**: No test input makes the loader raise; the import-marker test proves no code runs.
- **SC-004**: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/` and
  `uv run pytest --cov=ziran` (at least 85%) pass. No new dependency.
