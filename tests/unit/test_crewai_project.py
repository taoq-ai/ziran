"""Tests for the static CrewAI project reader (spec 056)."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from ziran.domain.entities.crewai import CrewAIAgent, CrewAIIssue, CrewAIScan, CrewAITask
from ziran.infrastructure.config.claude_code_plugin import MAX_FILE_BYTES
from ziran.infrastructure.config.crewai_project import MAX_AST_DEPTH, load_crewai

if TYPE_CHECKING:
    from pathlib import Path

PLANTED = "ziran-planted-content-056"


def _project(
    root: Path,
    agents: str,
    tasks: str = "",
    crew: str | None = None,
    pkg: str = "src/demo",
) -> Path:
    """Write a CrewAI src layout under *root*; return the config directory."""
    cfg = root / pkg / "config"
    cfg.mkdir(parents=True)
    (cfg / "agents.yaml").write_text(agents, encoding="utf-8")
    (cfg / "tasks.yaml").write_text(tasks, encoding="utf-8")
    if crew is not None:
        (cfg.parent / "crew.py").write_text(crew, encoding="utf-8")
    return cfg


def _units(scan: CrewAIScan) -> dict[str, CrewAIAgent]:
    return {a.name: a for a in scan.agents}


def _messages(scan: CrewAIScan) -> list[str]:
    return [i.message for i in scan.issues] + [e.message for a in scan.agents for e in a.errors]


CREW_HEAD = (
    "from crewai import Agent, Crew, Task\n"
    "from crewai.project import CrewBase, agent, crew, task\n"
    "from crewai_tools import FileReadTool, SerperDevTool\n\n"
    "@CrewBase\n"
    "class Demo:\n"
)


# ── Domain models ─────────────────────────────────────────────────────


@pytest.mark.unit
class TestModels:
    def test_tools_union_order_and_dedup(self) -> None:
        agent = CrewAIAgent(
            name="a",
            file="agents.yaml",
            agent_tools=["A", "B"],
            tasks=[CrewAITask(name="t1", tools=["B", "C"]), CrewAITask(name="t2", tools=["D"])],
        )
        assert agent.tools == ["A", "B", "C", "D"]

    def test_empty_tool_set(self) -> None:
        assert CrewAIAgent(name="a", file="f").tools == []

    def test_detected(self) -> None:
        assert not CrewAIScan(root=".").detected
        assert CrewAIScan(root=".", agents=[CrewAIAgent(name="a", file="f")]).detected
        assert CrewAIScan(root=".", issues=[CrewAIIssue(file="f", message="m")]).detected


# ── Discovery ─────────────────────────────────────────────────────────


@pytest.mark.unit
class TestDiscovery:
    def test_directory(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path, "researcher:\n  role: R\n  tools: [search_tool]\n")
        scan = load_crewai(tmp_path)
        [unit] = scan.agents
        assert (unit.name, unit.file, unit.line) == ("researcher", str(cfg / "agents.yaml"), 1)
        assert unit.agent_tools == ["search_tool"]
        assert unit.errors == []
        assert scan.files_analyzed == 2
        assert scan.issues == []

    def test_agents_yaml_file_target(self, tmp_path: Path) -> None:
        cfg = _project(
            tmp_path,
            "researcher:\n  role: R\n",
            crew=CREW_HEAD
            + "    @agent\n    def researcher(self) -> Agent:\n"
            + "        return Agent(config=self.agents_config['researcher'], tools=[X()])\n",
        )
        scan = load_crewai(cfg / "agents.yaml")
        assert _units(scan)["researcher"].agent_tools == ["X"]
        assert scan.issues == []

    def test_other_file_target_is_empty(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path, "researcher:\n  role: R\n")
        assert not load_crewai(cfg / "tasks.yaml").detected
        assert not load_crewai(tmp_path / "missing").detected

    def test_agents_yaml_without_tasks_yaml(self, tmp_path: Path) -> None:
        (tmp_path / "agents.yaml").write_text("researcher:\n  tools: [a, b]\n")
        assert not load_crewai(tmp_path).detected
        assert not load_crewai(tmp_path / "agents.yaml").detected

    def test_skip_dirs(self, tmp_path: Path) -> None:
        _project(tmp_path, "a:\n  role: R\n", pkg=".venv/lib/pkg")
        _project(tmp_path, "b:\n  role: R\n", pkg="node_modules/pkg")
        assert not load_crewai(tmp_path, skip_dirs=[".venv", "node_modules"]).detected
        assert len(load_crewai(tmp_path).agents) == 2

    def test_several_projects_in_path_order(self, tmp_path: Path) -> None:
        _project(tmp_path, "z1:\n  role: R\nz2:\n  role: R\n", pkg="b/src/b")
        _project(tmp_path, "y:\n  role: R\n", pkg="a/src/a")
        assert [a.name for a in load_crewai(tmp_path).agents] == ["y", "z1", "z2"]

    def test_empty_agents_yaml_is_not_a_project(self, tmp_path: Path) -> None:
        _project(tmp_path, "")
        scan = load_crewai(tmp_path)
        assert scan.agents == [] and scan.issues == []

    def test_crew_py_inside_config_dir(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path, "a:\n  role: R\n")
        (cfg / "crew.py").write_text(
            CREW_HEAD + "    @agent\n    def a(self) -> Agent:\n        return Agent(tools=[T()])\n"
        )
        assert _units(load_crewai(tmp_path))["a"].agent_tools == ["T"]


# ── Tool sets ─────────────────────────────────────────────────────────


@pytest.mark.unit
class TestToolSets:
    def test_yaml_tools_none_is_empty(self, tmp_path: Path) -> None:
        _project(tmp_path, "a:\n  role: R\n  tools:\n")
        [unit] = load_crewai(tmp_path).agents
        assert unit.agent_tools == [] and unit.errors == []

    def test_crew_argument_replaces_yaml(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "researcher:\n  role: R\n  tools: [yaml_tool]\n",
            crew=CREW_HEAD
            + "    @agent\n    def researcher(self) -> Agent:\n"
            + "        return Agent(config=self.agents_config['researcher'],"
            + " tools=[SerperDevTool()])\n",
        )
        assert _units(load_crewai(tmp_path))["researcher"].agent_tools == ["SerperDevTool"]

    def test_explicit_none_argument_keeps_yaml(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\n  tools: [yaml_tool]\n",
            crew=CREW_HEAD
            + "    @agent\n    def a(self) -> Agent:\n        return Agent(tools=None)\n",
        )
        assert _units(load_crewai(tmp_path))["a"].agent_tools == ["yaml_tool"]

    def test_config_key_maps_method_to_entry(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "writer:\n  role: W\n",
            tasks=(
                "draft:\n  description: d\n  agent: write_agent\n  tools: [send_email]\n"
                "review:\n  description: r\n"
            ),
            crew=CREW_HEAD
            + "    @agent\n    def write_agent(self) -> Agent:\n"
            + "        return Agent(config=self.agents_config['writer'], tools=[FileReadTool()])\n"
            + "    @task\n    def review(self) -> Task:\n"
            + "        return Task(config=self.tasks_config['review'], agent=self.write_agent(),"
            + " tools=[self.lookup()])\n",
        )
        unit = _units(load_crewai(tmp_path))["writer"]
        assert unit.agent_tools == ["FileReadTool"]
        assert [(t.name, t.tools) for t in unit.tasks] == [
            ("draft", ["send_email"]),
            ("review", ["lookup"]),
        ]
        assert unit.tools == ["FileReadTool", "send_email", "lookup"]
        assert unit.errors == []

    def test_crew_only_task(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "researcher:\n  role: R\n",
            crew=CREW_HEAD
            + "    @task\n    def extra(self) -> Task:\n"
            + "        return Task(description='x', agent=self.researcher(), tools=[X()])\n",
        )
        unit = _units(load_crewai(tmp_path))["researcher"]
        assert [(t.name, t.tools) for t in unit.tasks] == [("extra", ["X"])]

    def test_task_tools_follow_precedence(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\n",
            tasks="t:\n  agent: a\n  tools: [yaml_tool]\n",
            crew=CREW_HEAD
            + "    @task\n    def t(self) -> Task:\n"
            + "        return Task(config=self.tasks_config['t'], tools=[crew_tool])\n",
        )
        assert _units(load_crewai(tmp_path))["a"].tasks[0].tools == ["crew_tool"]

    def test_tool_name_forms(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\n",
            crew=CREW_HEAD
            + "    @agent\n    def a(self) -> Agent:\n"
            + "        return Agent(tools=[SerperDevTool(), crewai_tools.FileReadTool(path='x'),"
            + " self.my_tool(), search, self.search])\n",
        )
        assert _units(load_crewai(tmp_path))["a"].agent_tools == [
            "SerperDevTool",
            "FileReadTool",
            "my_tool",
            "search",
        ]

    def test_tool_ids_are_verbatim(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\n  tools: [Search_Tool, search_tool, FileReadTool]\n",
        )
        units = _units(load_crewai(tmp_path))
        assert units["a"].agent_tools == ["Search_Tool", "search_tool", "FileReadTool"]

    def test_crew_tool_ids_are_verbatim(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "b:\n  role: R\n",
            crew=CREW_HEAD
            + "    @agent\n    def b(self) -> Agent:\n"
            + "        return Agent(tools=[FileReadTool(), fileReadTool(), FileRead()])\n",
        )
        assert _units(load_crewai(tmp_path))["b"].agent_tools == [
            "FileReadTool",
            "fileReadTool",
            "FileRead",
        ]

    def test_decorator_forms_and_tuple(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\n",
            crew=CREW_HEAD
            + "    @project.agent\n    def a(self) -> Agent:\n"
            + "        result = crewai.Agent(tools=(T1(), T2()))\n        return result\n",
        )
        assert _units(load_crewai(tmp_path))["a"].agent_tools == ["T1", "T2"]

    def test_unassigned_task_and_unknown_agent(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\n",
            tasks="t1:\n  tools: [x]\nt2:\n  agent: ghost\n  tools: [y]\n",
        )
        [unit] = load_crewai(tmp_path).agents
        assert unit.tasks == [] and unit.errors == []

    def test_agent_method_without_entry_is_not_a_unit(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\n",
            crew=CREW_HEAD
            + "    @agent\n    def b(self) -> Agent:\n        return Agent(tools=[T()])\n",
        )
        assert [u.name for u in load_crewai(tmp_path).agents] == ["a"]

    def test_line_of_each_entry(self, tmp_path: Path) -> None:
        _project(tmp_path, "# c\na:\n  role: R\n\nb:\n  role: R\n")
        assert [(u.name, u.line) for u in load_crewai(tmp_path).agents] == [("a", 2), ("b", 5)]


# ── Hostile and broken input ──────────────────────────────────────────


def _all_errors(scan: CrewAIScan) -> list[CrewAIIssue]:
    return [e for a in scan.agents for e in a.errors]


@pytest.mark.unit
class TestHostileInput:
    def test_crew_py_is_never_executed(self, tmp_path: Path) -> None:
        marker = tmp_path / "executed"
        crew = (
            f"open({str(marker)!r}, 'w').write('x')\n"
            "raise SystemExit(3)\n"
            + CREW_HEAD
            + "    @agent\n    def a(self) -> Agent:\n"
            + f"        open({str(marker)!r}, 'w').write('x')\n"
            + "        return Agent(tools=[T()])\n"
        )
        _project(tmp_path, "a:\n  role: R\n", crew=crew)
        scan = load_crewai(tmp_path)
        assert not marker.exists()
        assert _units(scan)["a"].agent_tools == ["T"]

    def test_yaml_python_tags_are_not_constructed(self, tmp_path: Path) -> None:
        marker = tmp_path / "executed"
        _project(
            tmp_path,
            f"a: !!python/object/apply:os.system ['touch {marker}']\n",
        )
        scan = load_crewai(tmp_path)
        assert not marker.exists()
        assert scan.agents == [] and len(scan.issues) == 1

    def test_syntax_error_keeps_yaml_tools(self, tmp_path: Path) -> None:
        cfg = _project(
            tmp_path,
            "a:\n  role: R\n  tools: [x]\nb:\n  role: R\n",
            crew=f"x = 1\ndef broken(:\n    '{PLANTED}'\n",
        )
        scan = load_crewai(tmp_path)
        units = _units(scan)
        assert units["a"].agent_tools == ["x"]
        for unit in units.values():
            [err] = unit.errors
            assert err.file == str(cfg.parent / "crew.py")
            assert err.line == 2
            assert "syntax" in err.message

    def test_null_byte(self, tmp_path: Path) -> None:
        _project(tmp_path, "a:\n  role: R\n", crew="x = 1\x00\n")
        [err] = load_crewai(tmp_path).agents[0].errors
        assert "Python" in err.message

    def test_oversized_agents_yaml(self, tmp_path: Path) -> None:
        _project(tmp_path, "a:\n  role: R\n" + "#" * MAX_FILE_BYTES)
        scan = load_crewai(tmp_path)
        assert scan.agents == []
        [issue] = scan.issues
        assert str(MAX_FILE_BYTES) in issue.message

    def test_oversized_crew_py(self, tmp_path: Path) -> None:
        _project(tmp_path, "a:\n  role: R\n", crew="#" * (MAX_FILE_BYTES + 1))
        [err] = load_crewai(tmp_path).agents[0].errors
        assert str(MAX_FILE_BYTES) in err.message

    def test_oversized_tasks_yaml(self, tmp_path: Path) -> None:
        _project(tmp_path, "a:\n  role: R\n", tasks="#" * (MAX_FILE_BYTES + 1))
        [err] = load_crewai(tmp_path).agents[0].errors
        assert err.file.endswith("tasks.yaml")

    def test_ast_deeper_than_limit(self, tmp_path: Path) -> None:
        _project(tmp_path, "a:\n  role: R\n", crew="x = " + "-" * (MAX_AST_DEPTH + 50) + "1\n")
        [err] = load_crewai(tmp_path).agents[0].errors
        assert f"deeper than {MAX_AST_DEPTH}" in err.message

    def test_ast_too_deep_for_the_parser(self, tmp_path: Path) -> None:
        # The parser itself fails (RecursionError or SyntaxError, by Python version).
        _project(tmp_path, "a:\n  role: R\n", crew="x = " + "-" * 200_000 + "1\n")
        [err] = load_crewai(tmp_path).agents[0].errors
        assert err.file.endswith("crew.py")

    def test_deep_yaml(self, tmp_path: Path) -> None:
        _project(tmp_path, "a: " + "[" * 100_000 + "\n")
        scan = load_crewai(tmp_path)
        assert scan.agents == [] and len(scan.issues) == 1

    def test_deep_tasks_yaml(self, tmp_path: Path) -> None:
        _project(tmp_path, "a:\n  role: R\n", tasks="t: " + "[" * 100_000 + "\n")
        [err] = load_crewai(tmp_path).agents[0].errors
        assert err.file.endswith("tasks.yaml")

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        _project(tmp_path, f"a:\n  role: R\n b: [{PLANTED}\n")
        scan = load_crewai(tmp_path)
        assert scan.agents == []
        [issue] = scan.issues
        assert issue.message.startswith("invalid YAML")
        assert issue.line is not None

    def test_agents_yaml_not_a_mapping(self, tmp_path: Path) -> None:
        _project(tmp_path, f"- {PLANTED}\n")
        scan = load_crewai(tmp_path)
        assert scan.agents == [] and len(scan.issues) == 1

    def test_tasks_yaml_not_a_mapping(self, tmp_path: Path) -> None:
        _project(tmp_path, "a:\n  role: R\nb:\n  role: R\n", tasks=f"- {PLANTED}\n")
        scan = load_crewai(tmp_path)
        assert all(len(u.errors) == 1 for u in scan.agents)

    def test_non_mapping_entries(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            f"a: {PLANTED}\nb:\n  role: R\n  tools: [ok]\n",
            tasks=f"t: {PLANTED}\n",
        )
        units = _units(load_crewai(tmp_path))
        assert units["a"].agent_tools == []
        assert len(units["a"].errors) == 2  # its own entry and the unattributable task
        assert units["b"].agent_tools == ["ok"]
        assert len(units["b"].errors) == 1

    @pytest.mark.parametrize("value", [PLANTED, f"[1, {PLANTED}]", "{k: v}"])
    def test_bad_yaml_tools_value(self, tmp_path: Path, value: str) -> None:
        _project(
            tmp_path,
            f"a:\n  role: R\n  tools: {value}\nb:\n  role: R\n",
            tasks=f"t:\n  agent: b\n  tools: {value}\n",
        )
        units = _units(load_crewai(tmp_path))
        assert units["a"].agent_tools == [] and len(units["a"].errors) == 1
        assert units["b"].tasks[0].tools == [] and len(units["b"].errors) == 1

    def test_non_string_task_agent(self, tmp_path: Path) -> None:
        _project(tmp_path, "a:\n  role: R\n", tasks="t:\n  agent: [a]\n")
        [err] = load_crewai(tmp_path).agents[0].errors
        assert err.file.endswith("tasks.yaml")

    def test_non_literal_tools_only_hits_its_unit(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\nb:\n  role: R\n",
            crew=CREW_HEAD
            + "    @agent\n    def a(self) -> Agent:\n"
            + "        return Agent(tools=self.get_tools())\n"
            + "    @agent\n    def b(self) -> Agent:\n"
            + "        return Agent(tools=[*base, T(), tools[0]])\n",
        )
        units = _units(load_crewai(tmp_path))
        [err_a] = units["a"].errors
        assert err_a.line == 9 and "literal list" in err_a.message
        assert units["b"].agent_tools == ["T"]
        assert [e.line for e in units["b"].errors] == [12, 12]

    def test_bad_task_tools_go_to_its_agent(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\nb:\n  role: R\n",
            crew=CREW_HEAD
            + "    @task\n    def t(self) -> Task:\n"
            + "        return Task(agent=self.a(), tools=make())\n",
        )
        units = _units(load_crewai(tmp_path))
        assert len(units["a"].errors) == 1 and units["b"].errors == []

    def test_unresolvable_task_agent_hits_every_unit(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\nb:\n  role: R\n",
            crew=CREW_HEAD
            + "    @task\n    def t(self) -> Task:\n"
            + "        return Task(agent=agents[0], tools=[T()])\n",
        )
        scan = load_crewai(tmp_path)
        assert all(len(u.errors) == 1 and u.tasks == [] for u in scan.agents)

    def test_method_without_factory_call(self, tmp_path: Path) -> None:
        _project(
            tmp_path,
            "a:\n  role: R\n  tools: [y]\n",
            crew=CREW_HEAD + "    @agent\n    def a(self) -> Agent:\n        return build()\n",
        )
        [unit] = load_crewai(tmp_path).agents
        assert unit.agent_tools == ["y"]
        [err] = unit.errors
        assert "Agent(" in err.message

    def test_symlink_escape(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside.py"
        outside.write_text("x = 1\n")
        root = tmp_path / "root"
        cfg = _project(root, "a:\n  role: R\n")
        os.symlink(outside, cfg.parent / "crew.py")
        [err] = load_crewai(root).agents[0].errors
        assert "outside" in err.message

    def test_symlinked_agents_yaml_escape(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside.yaml"
        outside.write_text("a:\n  role: R\n")
        root = tmp_path / "root"
        cfg = root / "config"
        cfg.mkdir(parents=True)
        (cfg / "tasks.yaml").write_text("")
        os.symlink(outside, cfg / "agents.yaml")
        scan = load_crewai(root)
        assert scan.agents == [] and len(scan.issues) == 1

    def test_undecodable_bytes(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path, "a:\n  role: R\n")
        (cfg.parent / "crew.py").write_bytes(b"\xff\xfe\xfa\x00bad")
        [err] = load_crewai(tmp_path).agents[0].errors
        assert "cannot read" in err.message

    def test_not_a_regular_file(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path, "a:\n  role: R\n")
        (cfg.parent / "crew.py").mkdir()
        [err] = load_crewai(tmp_path).agents[0].errors
        assert "regular file" in err.message

    def test_no_message_holds_file_content(self, tmp_path: Path) -> None:
        _project(tmp_path, f"a:\n  role: R\n b: [{PLANTED}\n", pkg="p1")
        _project(
            tmp_path,
            f"a: {PLANTED}\n",
            tasks=f"t: {PLANTED}\n",
            crew=f"x = '{PLANTED}'\ndef broken(:\n",
            pkg="p2",
        )
        _project(tmp_path, f"a: *{PLANTED}\n", pkg="p3")
        _project(tmp_path, f"a: !!python/name:{PLANTED} x\n", pkg="p4")
        scan = load_crewai(tmp_path)
        assert len(scan.issues) == 3
        assert all(PLANTED not in m for m in _messages(scan))
