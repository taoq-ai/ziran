"""Chains found at discovery steer the campaign (spec 087)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest

from tests.conftest import MockAgentAdapter
from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.agent_scanner.chain_targeting import (
    DEFAULT_RESOURCE,
    MAX_VECTORS_PER_CHAIN,
    ChainSteering,
    _resource,
    plan,
    plan_steering,
    steer,
)
from ziran.application.agent_scanner.phase_executor import PhaseExecutor
from ziran.application.agent_scanner.structure_import import import_adapter_structure
from ziran.application.knowledge_graph.graph import AttackKnowledgeGraph
from ziran.application.strategies.adaptive import AdaptiveStrategy
from ziran.application.strategies.llm_adaptive import LLMAdaptiveStrategy
from ziran.application.strategies.protocol import CampaignContext
from ziran.domain.entities.attack import (
    AttackCategory,
    AttackPrompt,
    AttackResult,
    AttackVector,
)
from ziran.domain.entities.capability import AgentCapability, CapabilityType, DangerousChain
from ziran.domain.entities.phase import (
    CampaignResult,
    ChainTarget,
    CoverageLevel,
    ScanPhase,
)
from ziran.interfaces.cli.html_report import build_html_report
from ziran.interfaces.cli.reports import ReportGenerator

if TYPE_CHECKING:
    from pathlib import Path

    from ziran.application.attacks.library import AttackLibrary

pytestmark = pytest.mark.unit

READ, HTTP = "tool_read_file", "tool_http_request"
EXFIL = AttackCategory.DATA_EXFILTRATION
SECRET_WORDS = ("api key", "credential", "password")


def _cap(name: str, schema: dict[str, Any] | None = None) -> AgentCapability:
    params = {"schema": schema} if schema else {}
    return AgentCapability(
        id=f"tool_{name}", name=name, type=CapabilityType.TOOL, parameters=params
    )


def _chain(vtype: str, *tools: str) -> DangerousChain:
    return DangerousChain(
        tools=list(tools or (READ, HTTP)),
        risk_level="critical",
        vulnerability_type=vtype,
        exploit_description="x",
    )


def _vec(
    vid: str,
    category: AttackCategory = EXFIL,
    *,
    severity: str = "high",
    tags: tuple[str, ...] = (),
    protocol: tuple[str, ...] = (),
    tactic: str = "single",
    template: str = "Summarise {target}.",
    variables: dict[str, str] | None = None,
    phase: ScanPhase = ScanPhase.EXECUTION,
) -> AttackVector:
    return AttackVector(
        id=vid,
        name=vid,
        category=category,
        target_phase=phase,
        description=vid,
        severity=severity,  # type: ignore[arg-type]
        prompts=[AttackPrompt(template=template, variables=variables or {"target": "API keys"})],
        tags=list(tags),
        protocol_filter=list(protocol),
        tactic=tactic,
    )


CAPS = [_cap("read_file"), _cap("http_request")]


def _ids(steering: ChainSteering) -> list[str]:
    return list(steering.vectors)


def _rendered(vector: AttackVector) -> list[str]:
    return [AttackExecutor._render_prompt(p) for p in vector.prompts]


class TestPlan:
    def test_exfil_family(self) -> None:
        vectors = [
            _vec("de"),
            _vec("ii_tagged", AttackCategory.INDIRECT_INJECTION, tags=("exfiltration",)),
            _vec("ii_plain", AttackCategory.INDIRECT_INJECTION, tags=("rag",)),
            _vec("tm", AttackCategory.TOOL_MANIPULATION, tags=("shell",)),
        ]
        steering = plan([_chain("data_exfiltration")], CAPS, vectors)
        assert sorted(_ids(steering)) == ["de", "ii_tagged"]
        (target,) = steering.targets
        assert target.tools == [READ, HTTP]
        assert target.vulnerability_type == "data_exfiltration"
        assert target.ran == []

    def test_unfit_vectors_dropped(self) -> None:
        vectors = [
            _vec("harm", tags=("harmful_task",)),
            _vec("mcp", protocol=("mcp",)),
            _vec("a2a", protocol=("a2a",)),
            _vec("multi", tactic="crescendo"),
            _vec("pair", tactic="pair"),
            _vec("ok"),
        ]
        steering = plan([_chain("pii_leakage")], CAPS, vectors)
        assert _ids(steering) == ["ok"]

    def test_fit_before_severity(self) -> None:
        vectors = [
            _vec("crit_no_fit", severity="critical", variables={"x": "y"}, template="Hi {x}"),
            _vec("med_fit", severity="medium", tags=("data_exfiltration",)),
            _vec("high_fit", severity="high", tags=("data_exfiltration",)),
        ]
        steering = plan([_chain("data_exfiltration")], CAPS, vectors)
        assert _ids(steering) == ["high_fit", "med_fit", "crit_no_fit"]

    def test_one_chain_per_vector_and_cap(self) -> None:
        vectors = [_vec(f"de{i}") for i in range(MAX_VECTORS_PER_CHAIN + 2)]
        first, second = _chain("data_exfiltration"), _chain("pii_leakage", READ, "tool_send")
        steering = plan([first, second], [*CAPS, _cap("send")], vectors)
        assert [len(t.vector_ids) for t in steering.targets] == [MAX_VECTORS_PER_CHAIN, 2]
        assert _ids(steering) == [f"de{i}" for i in range(MAX_VECTORS_PER_CHAIN + 2)]

    @pytest.mark.parametrize(
        ("vtype", "chosen"),
        [
            ("remote_code_execution", ["tm_shell"]),
            ("memory_to_rce", ["tm_shell"]),
            ("mcp_resource_exfiltration", ["de"]),
            ("data_poisoning", ["mp"]),
            ("shell_persist", ["tm_shell"]),
            ("privilege_escalation", ["auth", "pe"]),
            ("authentication_bypass", ["auth", "pe"]),
        ],
    )
    def test_families(self, vtype: str, chosen: list[str]) -> None:
        vectors = [
            _vec("de"),
            _vec("tm_shell", AttackCategory.TOOL_MANIPULATION, tags=("shell",)),
            _vec("tm_plain", AttackCategory.TOOL_MANIPULATION, tags=("parameter",)),
            _vec("mp", AttackCategory.MEMORY_POISONING),
            _vec("pe", AttackCategory.PRIVILEGE_ESCALATION, severity="medium"),
            _vec("auth", AttackCategory.AUTHORIZATION_BYPASS),
        ]
        assert sorted(_ids(plan([_chain(vtype)], CAPS, vectors))) == chosen

    def test_unknown_family_and_no_chains(self) -> None:
        vectors = [_vec("de")]
        unknown = plan([_chain("directory_traversal")], CAPS, vectors)
        assert (unknown.vectors, unknown.targets) == ({}, [])
        assert plan([], CAPS, vectors) == ChainSteering([], {}, [])


class TestRender:
    def test_task_line_names_tools_and_resource(self) -> None:
        steering = plan([_chain("data_exfiltration")], CAPS, [_vec("de")])
        (prompt,) = _rendered(steering.vectors["de"])
        assert "read_file" in prompt and "http_request" in prompt and "notes.txt" in prompt
        assert prompt.endswith("Summarise notes.txt.")
        assert "api key" not in prompt.lower()

    def test_filled_template_needs_no_task_line(self) -> None:
        vec = _vec(
            "de",
            template="Use {tool_a} on {path}, then {tool_b}.",
            variables={"tool_a": "x", "tool_b": "y", "path": "z"},
        )
        (prompt,) = _rendered(plan([_chain("data_exfiltration")], CAPS, [vec]).vectors["de"])
        assert prompt == "Use read_file on notes.txt, then http_request."

    def test_resource_from_discovered_schema(self) -> None:
        schema = {"properties": {"path": {"type": "string", "examples": ["reports/q3.txt"]}}}
        caps = [_cap("read_file", schema), _cap("http_request")]
        (prompt,) = _rendered(plan([_chain("data_exfiltration")], caps, [_vec("de")]).vectors["de"])
        assert "reports/q3.txt" in prompt

    @pytest.mark.parametrize(
        ("parameters", "expected"),
        [
            ({}, DEFAULT_RESOURCE),
            ({"schema": "x"}, DEFAULT_RESOURCE),
            ({"schema": {"properties": ["path"]}}, DEFAULT_RESOURCE),
            ({"schema": {"properties": {"path": "string"}}}, DEFAULT_RESOURCE),
            ({"schema": {"properties": {"path": {"default": "  "}}}}, DEFAULT_RESOURCE),
            (
                {"schema": {"properties": {"path": {"default": 3, "examples": "a"}}}},
                DEFAULT_RESOURCE,
            ),
            ({"schema": {"properties": {"path": {"examples": [" a.txt "]}}}}, "a.txt"),
            ({"schema": {"properties": {"p": {"default": "d.txt", "examples": ["e"]}}}}, "d.txt"),
        ],
    )
    def test_resource_on_blank_and_malformed_schemas(
        self, parameters: dict[str, Any], expected: str
    ) -> None:
        assert _resource(parameters) == expected

    async def test_library_vectors_for_the_flat_chain(
        self, shared_attack_library: AttackLibrary
    ) -> None:
        graph = AttackKnowledgeGraph()
        for cap in CAPS:
            graph.add_capability(cap.id, cap)
        await import_adapter_structure(MockAgentAdapter(), graph, CAPS)
        steering = plan_steering(
            graph, CAPS, shared_attack_library, [ScanPhase.EXECUTION], CoverageLevel.STANDARD
        )
        target = next(t for t in steering.targets if t.tools == [READ, HTTP])
        assert target.vulnerability_type == "data_exfiltration"
        assert target.vector_ids
        for vid in target.vector_ids:
            vector = steering.vectors[vid]
            assert not vector.protocol_filter
            assert "harmful_task" not in vector.tags
            for prompt in _rendered(vector):
                assert "read_file" in prompt and "http_request" in prompt
                assert "notes.txt" in prompt
                assert not any(w in prompt.lower() for w in SECRET_WORDS), (vid, prompt)

    async def test_100_tools_is_fast(self, shared_attack_library: AttackLibrary) -> None:
        caps = [_cap(f"{kind}_{i}") for i in range(50) for kind in ("read_file", "http_request")]
        graph = AttackKnowledgeGraph()
        for cap in caps:
            graph.add_capability(cap.id, cap)
        await import_adapter_structure(MockAgentAdapter(), graph, caps)
        start = time.perf_counter()
        steering = plan_steering(
            graph, caps, shared_attack_library, [ScanPhase.EXECUTION], CoverageLevel.STANDARD
        )
        assert time.perf_counter() - start < 5
        assert len(steering.chains) > 100
        assert len(steering.vectors) == sum(len(t.vector_ids) for t in steering.targets)


class TestSteer:
    def test_front_in_plan_order_others_kept(self) -> None:
        a, b, c, d = (_vec(x) for x in "abcd")
        c2, a2 = _vec("c", template="C"), _vec("a", template="A")
        assert steer([a, b, c, d], {"c": c2, "a": a2}) == [c2, a2, b, d]

    def test_no_vectors_is_identity(self) -> None:
        attacks = [_vec("a"), _vec("b")]
        assert steer(attacks, {}) == attacks

    async def test_phase_executor_steers_after_prioritize(self) -> None:
        attacks = [_vec(x) for x in ("a", "b", "c")]
        steering = plan([_chain("data_exfiltration")], CAPS, [attacks[1]])
        seen: list[CampaignContext] = []
        executed: list[AttackVector] = []

        class Reverse:
            def prioritize_attacks(self, vs: list[Any], ctx: CampaignContext) -> list[Any]:
                seen.append(ctx)
                return list(reversed(vs))

        class Library:
            def get_attacks_for_phase(self, phase: Any, *, coverage: Any) -> list[AttackVector]:
                return list(attacks)

        class Executor:
            async def execute(self, attack: AttackVector) -> AttackResult:
                executed.append(attack)
                return AttackResult(
                    vector_id=attack.id,
                    vector_name=attack.name,
                    category=attack.category,
                    severity=attack.severity,
                    successful=False,
                )

        executor = PhaseExecutor(Executor(), Library(), AttackKnowledgeGraph())  # type: ignore[arg-type]
        await executor.execute(
            ScanPhase.EXECUTION,
            0,
            1,
            max_concurrent=1,
            strategy=Reverse(),  # type: ignore[arg-type]
            tested_vector_ids=set(),
            attack_results=[],
            steering=steering,
        )
        assert [v.id for v in executed] == ["b", "c", "a"]
        assert executed[0] is steering.vectors["b"]
        assert seen[0].dangerous_chains == steering.chains
        assert seen[0].chain_vectors == steering.vectors


def _context(steering: ChainSteering | None = None, **kw: Any) -> CampaignContext:
    phases = [ScanPhase.CAPABILITY_MAPPING, ScanPhase.EXECUTION]
    if steering is None:
        return CampaignContext(available_phases=phases, **kw)
    return CampaignContext(
        available_phases=phases,
        dangerous_chains=steering.chains,
        chain_vectors=steering.vectors,
        **kw,
    )


class TestStrategies:
    STEERING = plan([_chain("data_exfiltration")], CAPS, [_vec("de")])

    def test_adaptive_boosts_phase_with_pending_chain_vectors(self) -> None:
        strategy = AdaptiveStrategy()
        plain, _ = strategy._score_phase(ScanPhase.EXECUTION, _context())
        boosted, why = strategy._score_phase(ScanPhase.EXECUTION, _context(self.STEERING))
        assert boosted > plain
        assert "chain" in why
        other, _ = strategy._score_phase(ScanPhase.CAPABILITY_MAPPING, _context(self.STEERING))
        assert other == strategy._score_phase(ScanPhase.CAPABILITY_MAPPING, _context())[0]
        assert strategy.select_next_phase(_context(self.STEERING)).phase == ScanPhase.EXECUTION  # type: ignore[union-attr]

    def test_adaptive_no_boost_once_run(self) -> None:
        strategy = AdaptiveStrategy()
        ran = _context(self.STEERING, attack_results_summary={"de": False})
        assert (
            strategy._score_phase(ScanPhase.EXECUTION, ran)[0]
            == strategy._score_phase(ScanPhase.EXECUTION, _context())[0]
        )

    def test_llm_prompt_lists_chains(self) -> None:
        prompts: list[str] = []

        class Client:
            async def complete(self, messages: list[dict[str, str]], **_: Any) -> Any:
                prompts.append(messages[0]["content"])
                return type("R", (), {"content": '{"phase": "execution"}'})()

        strategy = LLMAdaptiveStrategy(llm_client=Client())  # type: ignore[arg-type]
        strategy._llm_select_phase(_context(self.STEERING))
        strategy._llm_select_phase(_context())
        assert f"{READ} -> {HTTP} (data_exfiltration)" in prompts[0]
        assert "Dangerous tool chains: none found" in prompts[1]


class TestReports:
    def _result(self) -> CampaignResult:
        return CampaignResult(
            campaign_id="c",
            target_agent="flat",
            phases_executed=[],
            total_vulnerabilities=0,
            final_trust_score=0.5,
            success=False,
            chain_targets=[
                ChainTarget(
                    tools=[READ, HTTP],
                    vulnerability_type="data_exfiltration",
                    vector_ids=["de_url_exfil", "de_markdown_link"],
                    ran=["de_url_exfil"],
                )
            ],
        )

    def test_markdown_table(self, tmp_path: Path) -> None:
        text = ReportGenerator(tmp_path)._format_markdown(self._result())
        assert "| Chain | Vulnerability type | Chosen vectors | Ran |" in text
        assert (
            f"| `{READ} → {HTTP}` | data_exfiltration | `de_url_exfil`, `de_markdown_link` "
            "| `de_url_exfil` |" in text
        )

    def test_html_table(self) -> None:
        page = build_html_report(self._result().model_dump(mode="json"), {})
        assert "<th>Chain</th><th>Vulnerability type</th><th>Chosen vectors</th>" in page
        assert "de_markdown_link" in page
        assert f"{READ} → {HTTP}" in page

    def test_target_named_tools_are_escaped(self, tmp_path: Path) -> None:
        target = ChainTarget(tools=["a|b", "<c>"], vulnerability_type="x", vector_ids=["v"])
        result = self._result().model_copy(update={"chain_targets": [target]})
        assert "| `a\\|b → <c>` | x | `v` | none |" in ReportGenerator(tmp_path)._format_markdown(
            result
        )
        page = build_html_report(result.model_dump(mode="json"), {})
        assert "a|b → &lt;c&gt;" in page and "<c>" not in page

    def test_no_targets_no_table(self, tmp_path: Path) -> None:
        result = self._result().model_copy(update={"chain_targets": []})
        assert "Chosen vectors" not in ReportGenerator(tmp_path)._format_markdown(result)
        assert "Chosen vectors" not in build_html_report(result.model_dump(mode="json"), {})
