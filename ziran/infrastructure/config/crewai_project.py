"""Read CrewAI projects statically: agents.yaml and tasks.yaml with ``yaml.safe_load``, crew.py
with ``ast.parse``. Project code is never imported, executed or evaluated.

Discovery for ``load_crewai(path)``:

* ``path`` is a file named ``agents.yaml``: its directory is the project when ``tasks.yaml`` is
  beside it. Files are read from the directory above (where crew.py lives) downwards.
* ``path`` is a directory: every directory below it (symlinked directories and ``skip_dirs`` are
  not walked) that holds both ``agents.yaml`` and ``tasks.yaml`` is a project.
* crew.py is ``config/../crew.py``, else ``config/crew.py``.

A unit is one agents.yaml entry. Its agent tools are the ``tools=`` argument of the matching
``@agent`` method (the one whose ``config=self.agents_config['<key>']`` names the entry, else the
method of the same name) when that argument is set, else the entry's ``tools:`` key. Tasks follow
the same rule for ``tools`` and ``agent``; that is how CrewAI's ``process_config`` merges an
explicit argument with its YAML config. In an ``@agent``/``@task`` method the first ``Agent(...)``/
``Task(...)`` call in ``ast.walk`` order is read. A tool element gives its called or referenced
name; a name bound in crew.py only by simple assignments calling one callee gives that callee; any
other element gives its source text.

Nothing in a file makes this raise. A failure that only touches one unit becomes an error on that
unit; a failure in tasks.yaml or crew.py that could touch any unit becomes an error on every unit
of the project; an unusable agents.yaml becomes a scan issue. Messages never hold file content
beyond key and method names.
"""

from __future__ import annotations

import ast
import os
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import yaml

from ziran.domain.entities.crewai import CrewAIAgent, CrewAIIssue, CrewAIScan, CrewAITask
from ziran.infrastructure.config.claude_code_plugin import MAX_FILE_BYTES

if TYPE_CHECKING:
    from collections.abc import Collection, Iterator

MAX_AST_DEPTH: Final = 200


class _UnusableError(Exception):
    def __init__(self, file: Path, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.issue = _issue(file, message, line)


def _real(path: Path) -> Path:
    return Path(os.path.realpath(path))  # never raises, even on symlink loops


def _read(file: Path, base: Path) -> str:
    real = _real(file)
    if not real.is_relative_to(base):
        raise _UnusableError(file, "file resolves outside the scanned root")
    if not real.is_file():
        raise _UnusableError(file, "not a regular file")
    try:
        with real.open("rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise _UnusableError(file, f"file is larger than {MAX_FILE_BYTES} bytes")
        return data.decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise _UnusableError(file, f"cannot read file ({type(exc).__name__})") from None


def _yaml(file: Path, base: Path) -> tuple[Any, dict[str, int]]:
    """(document, top-level key -> 1-based line)."""
    text = _read(file, base)
    try:
        data = yaml.safe_load(text)
        node = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        # Class name only: str(exc) and exc.problem can quote source text (aliases, tags).
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else None
        raise _UnusableError(file, f"invalid YAML ({type(exc).__name__})", line) from None
    except RecursionError:
        raise _UnusableError(file, "YAML is nested too deeply") from None
    lines = (
        {str(k.value): k.start_mark.line + 1 for k, _ in node.value}
        if isinstance(node, yaml.MappingNode)
        else {}
    )
    return data, lines


def _python(file: Path, base: Path) -> ast.Module:
    text = _read(file, base)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # SyntaxWarning for odd escapes is noise here
            tree = ast.parse(text, filename=str(file))
    except SyntaxError as exc:
        raise _UnusableError(file, "invalid Python syntax", exc.lineno) from None
    except (ValueError, RecursionError, MemoryError):
        raise _UnusableError(file, "cannot parse Python source") from None
    if _too_deep(tree):
        raise _UnusableError(file, f"Python AST is deeper than {MAX_AST_DEPTH} levels")
    return tree


def _too_deep(tree: ast.AST) -> bool:
    stack = [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_AST_DEPTH:
            return True
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return False


def _ref(node: ast.AST) -> str | None:
    """Referenced name: the callee of a call, an identifier, or the last attribute."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _yaml_tools(value: object) -> list[str] | None:
    """Tool names of a YAML ``tools:`` value; None when the value is not a list of strings."""
    if value is None:
        return []
    if isinstance(value, list) and all(isinstance(t, str) for t in value):
        return list(dict.fromkeys(value))
    return None


@dataclass
class _Method:
    """What an ``@agent``/``@task`` method passes to ``Agent(...)``/``Task(...)``."""

    name: str
    key: str
    tools: list[str] | None = None  # None: no tools= argument
    agent: str | None = None  # task only: referenced agent method
    agent_unresolved: bool = False
    errors: list[CrewAIIssue] = field(default_factory=list)


def _bindings(tree: ast.Module) -> dict[str, str]:
    """Names whose every binding in the file is a simple assignment calling one callee."""
    simple: dict[int, str | None] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        else:
            continue
        simple[id(target)] = _ref(value) if isinstance(value, ast.Call) else None
    callees: dict[str, set[str | None]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            callees.setdefault(node.id, set()).add(simple.get(id(node)))
    resolved: dict[str, str] = {}
    for name, found in callees.items():
        callee = found.pop() if len(found) == 1 else None
        if callee:
            resolved[name] = callee
    return resolved


def _methods(
    tree: ast.Module, file: Path, decorator: str, factory: str, bindings: dict[str, str]
) -> Iterator[_Method]:
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if not any(_ref(d) == decorator for d in fn.decorator_list):
            continue
        owner = f"@{decorator} method '{fn.name}'"
        call = next(
            (n for n in ast.walk(fn) if isinstance(n, ast.Call) and _ref(n.func) == factory),
            None,
        )
        if call is None:
            yield _Method(
                fn.name,
                fn.name,
                errors=[_issue(file, f"no {factory}(...) call in {owner}", fn.lineno)],
            )
            continue
        kwargs = {
            kw.arg: kw.value
            for kw in call.keywords
            if kw.arg and not (isinstance(kw.value, ast.Constant) and kw.value.value is None)
        }
        method = _Method(fn.name, _config_key(kwargs.get("config")) or fn.name)
        if "tools" in kwargs:
            method.tools = _tool_list(kwargs["tools"], file, owner, method.errors, bindings)
        if "agent" in kwargs:
            method.agent = _ref(kwargs["agent"])
            if method.agent is None:
                method.agent_unresolved = True
                method.errors.append(
                    _issue(file, f"agent of {owner} is not a reference", kwargs["agent"].lineno)
                )
        yield method


def _config_key(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        key = node.slice.value
        return key if isinstance(key, str) else None
    return None


def _tool_list(
    node: ast.expr, file: Path, owner: str, errors: list[CrewAIIssue], bindings: dict[str, str]
) -> list[str]:
    """FR-007: a bound name gives its callee, a call, name or attribute its name, else source text."""
    if not isinstance(node, ast.List | ast.Tuple):
        errors.append(_issue(file, f"tools of {owner} is not a literal list", node.lineno))
        return []
    names = [
        bindings.get(e.id, e.id) if isinstance(e, ast.Name) else _ref(e) or ast.unparse(e)
        for e in node.elts
    ]
    return list(dict.fromkeys(names))


def _issue(file: Path, message: str, line: int | None = None) -> CrewAIIssue:
    return CrewAIIssue(file=str(file), line=line, message=message)


_Task = tuple[str, str | None, list[str], list[CrewAIIssue]]  # name, agent ref, tools, errors


class _Project:
    """One config directory. Errors are keyed by unit name; ``None`` means every unit."""

    def __init__(self, config_dir: Path, base: Path) -> None:
        self.agents_file = config_dir / "agents.yaml"
        self.tasks_file = config_dir / "tasks.yaml"
        crew_files = (config_dir.parent / "crew.py", config_dir / "crew.py")
        self.crew_file = next((p for p in crew_files if os.path.lexists(p)), None)
        self.base = base
        self.errors: dict[str | None, list[CrewAIIssue]] = {}

    def error(self, unit: str | None, issue: CrewAIIssue) -> None:
        self.errors.setdefault(unit, []).append(issue)

    def read(self, scan: CrewAIScan) -> None:
        try:
            agents, lines = _yaml(self.agents_file, self.base)
        except _UnusableError as exc:
            scan.issues.append(exc.issue)
            return
        scan.files_analyzed += 1
        if agents is None:
            return
        if not isinstance(agents, dict):
            scan.issues.append(_issue(self.agents_file, "agents.yaml must be a mapping"))
            return

        agent_methods, task_methods = self.crew()
        units: dict[str, CrewAIAgent] = {}
        for key, entry in agents.items():
            name, line = str(key), lines.get(str(key), 1)
            unit = CrewAIAgent(name=name, file=str(self.agents_file), line=line)
            unit.agent_tools = self.entry_tools(name, line, entry)
            method = agent_methods.get(name)
            if method is not None:
                if method.tools is not None:
                    unit.agent_tools = method.tools
                for issue in method.errors:
                    self.error(name, issue)
            units[name] = unit

        to_key = {m.name: m.key for m in agent_methods.values()}
        for task, agent_ref, tools, errors in self.tasks(scan, task_methods):
            owner = units.get(to_key.get(agent_ref, agent_ref)) if agent_ref else None
            if owner is not None:
                owner.tasks.append(CrewAITask(name=task, tools=tools))
                for issue in errors:
                    self.error(owner.name, issue)

        for unit in units.values():
            unit.errors = [*self.errors.get(None, []), *self.errors.get(unit.name, [])]
            scan.agents.append(unit)

    def entry_tools(self, name: str, line: int, entry: object) -> list[str]:
        """Tools of an agents.yaml entry; a problem becomes an error on that unit."""
        if not isinstance(entry, dict):
            self.error(name, _issue(self.agents_file, f"entry '{name}' must be a mapping", line))
            return []
        tools = _yaml_tools(entry.get("tools"))
        if tools is None:
            message = f"tools of entry '{name}' must be a list of names"
            self.error(name, _issue(self.agents_file, message, line))
            return []
        return tools

    def crew(self) -> tuple[dict[str, _Method], dict[str, _Method]]:
        """``@agent`` and ``@task`` methods by config key; a crew.py failure hits every unit."""
        if self.crew_file is None:
            return {}, {}
        try:
            tree = _python(self.crew_file, self.base)
        except _UnusableError as exc:
            self.error(None, exc.issue)
            return {}, {}
        bindings = _bindings(tree)
        agents = {m.key: m for m in _methods(tree, self.crew_file, "agent", "Agent", bindings)}
        tasks = {m.key: m for m in _methods(tree, self.crew_file, "task", "Task", bindings)}
        return agents, tasks

    def tasks(self, scan: CrewAIScan, methods: dict[str, _Method]) -> Iterator[_Task]:
        """Tasks in tasks.yaml order, then crew.py-only tasks. A task whose agent cannot be
        told puts its problem on every unit and is not yielded."""
        try:
            data, lines = _yaml(self.tasks_file, self.base)
            scan.files_analyzed += 1
        except _UnusableError as exc:
            self.error(None, exc.issue)
            data, lines = None, {}
        if data is not None and not isinstance(data, dict):
            self.error(None, _issue(self.tasks_file, "tasks.yaml must be a mapping"))
            data = None
        entries: dict[Any, Any] = data or {}

        for key, entry in entries.items():
            name, line = str(key), lines.get(str(key), 1)
            if not isinstance(entry, dict):
                self.error(None, _issue(self.tasks_file, f"entry '{name}' must be a mapping", line))
                continue
            agent = entry.get("agent")
            if agent is not None and not isinstance(agent, str):
                message = f"agent of entry '{name}' is not a name"
                self.error(None, _issue(self.tasks_file, message, line))
                continue
            errors: list[CrewAIIssue] = []
            tools = _yaml_tools(entry.get("tools"))
            if tools is None:
                message = f"tools of entry '{name}' must be a list of names"
                errors.append(_issue(self.tasks_file, message, line))
                tools = []
            yield from self.merge((name, agent, tools, errors), methods.get(name))

        for key, method in methods.items():
            if key not in entries:
                yield from self.merge((key, None, [], []), method)

    def merge(self, task: _Task, method: _Method | None) -> Iterator[_Task]:
        """Apply a task method's explicit arguments over the task's YAML values."""
        if method is None:
            yield task
            return
        if method.agent_unresolved:
            for issue in method.errors:
                self.error(None, issue)
            return
        name, agent, tools, errors = task
        yield (
            name,
            method.agent if method.agent is not None else agent,
            method.tools if method.tools is not None else tools,
            [*errors, *method.errors],
        )


def _project_dirs(path: Path, skip_dirs: Collection[str]) -> Iterator[Path]:
    for directory, subdirs, files in os.walk(path):
        subdirs[:] = sorted(d for d in subdirs if d not in skip_dirs)
        if "agents.yaml" in files and "tasks.yaml" in files:
            yield Path(directory)


def load_crewai(path: Path, skip_dirs: Collection[str] = ()) -> CrewAIScan:
    """Read every CrewAI project under *path*. Never raises for file content or missing files."""
    scan = CrewAIScan(root=str(path))
    if os.path.isdir(path):
        base, dirs = _real(path), sorted(_project_dirs(path, skip_dirs), key=str)
    elif path.name == "agents.yaml" and os.path.isfile(path.parent / "tasks.yaml"):
        base, dirs = _real(path.parent.parent), [path.parent]
    else:
        return scan
    for config_dir in dirs:
        _Project(config_dir, base).read(scan)
    return scan
