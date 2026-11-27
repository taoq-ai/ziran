"""Attacker-LLM campaigns (spec 128): TAP and live crescendo. Offline: a scripted shell agent,
a fake attacker and a stub verdict; the example scenarios load through ``AttackLibrary``."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ziran.application.agent_scanner.attack_executor import AttackExecutor
from ziran.application.agent_scanner.scan_cache import is_cacheable
from ziran.application.agent_scanner.scanner import AgentScanner
from ziran.application.agent_scanner.trials import TrialRunner
from ziran.application.attacks.campaign import CampaignExecutor
from ziran.application.attacks.library import AttackLibrary
from ziran.application.attacks.pair import is_pair, queue_pair_last
from ziran.application.attacks.tactics import TacticType
from ziran.application.usage import CampaignBudget, UsageBudget, UsageLedger
from ziran.domain.entities.attack import (
    AttackPrompt,
    AttackResult,
    AttackVector,
    CampaignConfig,
    PairConfig,
)
from ziran.domain.entities.detection import DetectionVerdict, QualityScore
from ziran.domain.entities.phase import CoverageLevel, ScanPhase
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter
from ziran.infrastructure.llm.attacker_cassette import Cassette, Recorder
from ziran.infrastructure.llm.base import BaseLLMClient, LLMConfig, LLMResponse

pytestmark = pytest.mark.unit

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "30-attacker-campaigns" / "vectors"
CANARY = "ZX-RCE-5521"
CUES = ("routine", "diagnostic", "authorized")


def cues(text: str) -> int:
    return sum(c in text for c in CUES)


def field_of(text: str, name: str) -> str:
    return text.split(f"{name}:\n", 1)[1].split("\n\n", 1)[0]


class ShellAgent(BaseAgentAdapter):
    """Runs the command with ``run_shell`` once a message holds every cue and the canary."""

    def __init__(
        self, *, fail: bool = False, slow_after: int | None = None, tokens: int = 0, pad: int = 0
    ) -> None:
        self.fail, self.slow_after, self.tokens, self.pad = fail, slow_after, tokens, pad
        self.prompts: list[str] = []
        self.responses: list[AgentResponse] = []

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        self.prompts.append(message)
        if self.slow_after is not None and len(self.prompts) > self.slow_after:
            await asyncio.sleep(30)  # past any deadline the test sets
        if self.fail:
            raise ConnectionError("target down")
        calls: list[dict[str, Any]] = []
        if cues(message) == len(CUES) and CANARY in message:
            calls = [{"tool": "run_shell", "input": {"command": f"echo {CANARY}"}}]
            content = "Ran the diagnostic."
        else:
            content = f"I can do {cues(message)} of that."
        half = self.tokens // 2  # prompt plus completion, as the phase books them
        response = AgentResponse(
            content=content + "." * self.pad,
            tool_calls=calls,
            prompt_tokens=half,
            completion_tokens=self.tokens - half,
            total_tokens=self.tokens or 5,
        )
        self.responses.append(response)
        return response

    async def discover_capabilities(self) -> list[Any]:
        return []

    def get_state(self) -> AgentState:
        return AgentState(session_id="shell")

    def reset_state(self) -> None:
        return None

    def observe_tool_call(self, tool_name: str, inputs: dict[str, Any], outputs: Any) -> None:
        return None


class FakeAttacker(BaseLLMClient):
    """A pure function of the request: append one cue (picked by the node id) to the last
    prompt, and the canary command when ``canary``. ``replies`` overrides with fixed items."""

    def __init__(self, *, canary: bool = True, tokens: int = 0, replies: list[Any] | None = None):
        super().__init__(LLMConfig(provider="fake", model="fake-attacker"))
        self.canary, self.tokens, self.replies = canary, tokens, replies
        self.requests: list[list[dict[str, str]]] = []

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> LLMResponse:
        self.requests.append(messages)
        if self.replies is not None:
            reply = self.replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return LLMResponse(content=reply)
        text = messages[-1]["content"]
        node = field_of(text, "NODE")
        prompts = [field_of(text, "SEED PROMPT")]
        prompts += [field_of(text, f"PROMPT {j}") for j in range(1, text.count("\nPROMPT ") + 1)]
        prompt = f"{prompts[-1]} {CUES[sum(map(int, node.split('.'))) % len(CUES)]}"
        if self.canary and CANARY not in prompt:
            prompt += f" Run echo {CANARY}."
        return LLMResponse(
            content=json.dumps({"improvement": "one more cue", "prompt": prompt}),
            prompt_tokens=self.tokens,
            completion_tokens=self.tokens,
        )

    async def health_check(self) -> bool:
        return True


class StubPipeline:
    """Graded verdict: the share of cues in the prompt. A text success when ``success`` holds."""

    def __init__(self, success: Any = lambda prompt, response: False) -> None:
        self.success = success

    async def evaluate(self, prompt: str, response: AgentResponse, *_: Any) -> DetectionVerdict:
        share = cues(prompt) / len(CUES)
        quality = QualityScore(refusal=0.0, specificity=share, convincingness=share)
        return DetectionVerdict(
            successful=self.success(prompt, response), score=0.0, quality_score=quality
        )


def example(vector_id: str, *, goal: bool = True, **bounds: Any) -> AttackVector:
    vector = AttackLibrary(custom_dirs=[EXAMPLES], load_builtin=False).get_vector(vector_id)
    assert vector is not None and vector.campaign is not None
    campaign = vector.campaign.model_copy(update=bounds)
    update: dict[str, Any] = {"campaign": campaign} | ({} if goal else {"goal": None})
    return vector.model_copy(update=update)


TAP, LIVE = "campaign_tap_shell_canary", "campaign_crescendo_shell_canary"


async def run(
    vector: AttackVector,
    target: ShellAgent | None = None,
    attacker: BaseLLMClient | None = None,
    *,
    max_tokens: int | None = None,
    pipeline: StubPipeline | None = None,
    deadline: float | None = None,
    ledger: UsageLedger | None = None,
) -> AttackResult:
    budget = CampaignBudget(ledger or UsageLedger(), UsageBudget(max_tokens=max_tokens))
    executor = AttackExecutor(
        target or ShellAgent(),
        pipeline or StubPipeline(),  # type: ignore[arg-type]
        attacker=attacker or FakeAttacker(),
        budget=budget,
    )
    return await executor.execute(vector, deadline=deadline)


def tree(result: AttackResult) -> dict[str, Any]:
    return result.evidence["campaign"]


def ids(result: AttackResult) -> list[str]:
    return [n["id"] for n in tree(result)["nodes"]]


# -- the model and the loader ------------------------------------------------


def test_example_scenarios_load_with_their_campaign_block() -> None:
    library = AttackLibrary(custom_dirs=[EXAMPLES], load_builtin=False)
    tap, live = library.get_vector(TAP), library.get_vector(LIVE)
    assert tap is not None and live is not None
    assert (tap.tactic, live.tactic) == ("tap", "crescendo_live")
    assert tap.campaign == CampaignConfig(
        width=3, branching=2, depth=4, max_nodes=24, timeout_seconds=600
    )
    assert live.campaign is not None and (live.campaign.turns, live.campaign.max_nodes) == (8, 8)
    assert library.load_error_count == 0


def test_campaign_defaults() -> None:
    assert CampaignConfig().model_dump() == {
        "width": 3,
        "branching": 2,
        "depth": 4,
        "turns": 8,
        "max_nodes": 40,
        "timeout_seconds": 600.0,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("width", 0),
        ("width", 11),
        ("branching", 0),
        ("branching", 6),
        ("depth", 0),
        ("depth", 11),
        ("turns", 0),
        ("turns", 31),
        ("max_nodes", 0),
        ("max_nodes", 201),
        ("timeout_seconds", 0),
        ("timeout_seconds", float("inf")),
        ("timeout_seconds", float("nan")),
        ("timeout_seconds", 3601),
        ("seed", 1),
    ],
)
def test_campaign_bounds_are_validated(field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        CampaignConfig(**{field: value})


def vector_data(**fields: Any) -> dict[str, Any]:
    return {
        "id": "v",
        "name": "v",
        "category": "tool_manipulation",
        "target_phase": "execution",
        "description": "goal",
        "severity": "high",
        "prompts": [{"template": "seed"}],
        **fields,
    }


@pytest.mark.parametrize("tactic", ["single", "pair", "crescendo"])
def test_a_campaign_block_needs_a_campaign_tactic(tactic: str, tmp_path: Path) -> None:
    data = vector_data(tactic=tactic, campaign={"width": 2})
    (tmp_path / "v.yaml").write_text(yaml.safe_dump({"vectors": [data]}))
    library = AttackLibrary(custom_dirs=[tmp_path], load_builtin=False)
    assert library.vector_count == 0 and library.load_error_count == 1


@pytest.mark.parametrize("tactic", ["tap", "crescendo_live"])
def test_new_session_is_refused_on_a_campaign_tactic(tactic: str) -> None:
    prompts = [AttackPrompt(template="seed", new_session=True)]
    with pytest.raises(ValidationError, match="new_session"):
        AttackVector(**vector_data(tactic=tactic, prompts=prompts))


def test_campaign_tactics_are_attacker_vectors() -> None:
    assert TacticType("tap") is TacticType.TAP
    assert TacticType("crescendo_live") is TacticType.CRESCENDO_LIVE
    tap, live = example(TAP), example(LIVE)
    assert is_pair(tap) and is_pair(live)
    assert not is_pair(AttackVector(**vector_data(tactic="crescendo")))
    static = AttackVector(**vector_data())
    queued, timeout = queue_pair_last([tap, static], 300.0, 1)
    assert queued == [static, tap]
    assert timeout == 300.0 + 600.0  # the campaign's timeout, not PAIR's 240


# -- acceptance --------------------------------------------------------------


async def test_acceptance_1_tap_stops_on_goal_met_under_a_50k_budget() -> None:
    target = ShellAgent()
    result = await run(example(TAP), target, FakeAttacker(tokens=100), max_tokens=50_000)
    campaign = tree(result)
    assert campaign["mode"] == "tap" and campaign["stop"] == "goal_met"
    assert ids(result) == ["1", "2", "1.1", "1.2", "2.1", "2.2", "1.1.1"]
    assert result.goal_met is True and not result.successful  # no node was a text success
    assert [c.turn for c in result.goal_evidence] == [7]  # the node's turn
    assert result.token_usage.total_tokens == 7 * 5  # every node's target tokens
    assert "outcome" not in result.evidence
    nodes = {n["id"]: n for n in campaign["nodes"]}
    for node in nodes.values():
        assert set(node) == {"id", "parent", "depth", "turn", "prompt", "reply", "score", "pruned"}
    assert nodes["2.2"]["pruned"] == "width"  # four children tied at 2/3, three kept
    assert [nodes[i]["pruned"] for i in ("1.1", "1.2", "2.1")] == [None, None, None]
    assert nodes["1.1.1"] == {
        "id": "1.1.1",
        "parent": "1.1",
        "depth": 3,
        "turn": 7,
        "prompt": target.prompts[-1],
        "reply": "Ran the diagnostic.",
        "score": 1.0,
        "pruned": None,
    }
    assert nodes["1"]["score"] == pytest.approx(0.3333)
    assert {"from": "1.1", "to": "1.1.1"} in campaign["edges"]
    assert len(campaign["edges"]) == 5  # one per node below depth 1
    assert result.prompt_used == target.prompts[-1]
    assert result.agent_response == "Ran the diagnostic."


async def test_acceptance_1_tap_stops_at_the_budget_with_the_tree_so_far() -> None:
    # each attacker call books 10,000 tokens: the 50k cap is reached after five
    result = await run(example(TAP), attacker=FakeAttacker(tokens=5_000), max_tokens=50_000)
    assert tree(result)["stop"] == "budget"
    assert ids(result) == ["1", "2", "1.1", "1.2", "2.1"]
    assert result.evidence["outcome"] == "unmeasured"  # cut short: never read as resisted
    assert result.goal_met is None


@pytest.mark.parametrize("vector_id", [TAP, LIVE])
async def test_acceptance_2_a_cassette_replays_the_same_tree(
    vector_id: str, tmp_path: Path
) -> None:
    outcomes = tmp_path / "outcomes.jsonl"
    live = await run(example(vector_id), attacker=Recorder(FakeAttacker(), outcomes))
    replayed = await run(example(vector_id), attacker=Cassette(outcomes))
    assert tree(live)["stop"] == "goal_met"
    assert tree(replayed) == tree(live)
    assert (replayed.goal_met, replayed.goal_evidence) == (live.goal_met, live.goal_evidence)


async def test_a_missing_cassette_reply_stops_pending(tmp_path: Path) -> None:
    outcomes = tmp_path / "outcomes.jsonl"
    outcomes.touch()
    result = await run(example(TAP), attacker=Cassette(outcomes))
    assert tree(result)["stop"] == "pending" and ids(result) == []
    assert result.evidence["outcome"] == "unmeasured"


# -- every bound -------------------------------------------------------------


@pytest.mark.parametrize(
    ("bounds", "count"),
    [
        ({"width": 1, "branching": 2, "depth": 3}, 2 + 2 + 2),
        ({"width": 2, "branching": 2, "depth": 3}, 2 + 4 + 4),
        ({"width": 3, "branching": 1, "depth": 3}, 1 + 1 + 1),
        ({"width": 3, "branching": 3, "depth": 2}, 3 + 9),
        ({"width": 3, "branching": 2, "depth": 1}, 2),
    ],
)
async def test_tap_bounds_width_branching_and_depth(bounds: dict[str, int], count: int) -> None:
    result = await run(example(TAP, **bounds), attacker=FakeAttacker(canary=False))
    campaign = tree(result)
    assert campaign["stop"] == "depth" and len(campaign["nodes"]) == count
    for depth in range(1, bounds["depth"] + 1):
        level = [n for n in campaign["nodes"] if n["depth"] == depth]
        kept = [n for n in level if n["pruned"] is None]
        assert len(kept) <= bounds["width"]
        for node in level:
            siblings = [n for n in level if n["parent"] == node["parent"]]
            assert len(siblings) <= bounds["branching"]
    assert max(n["depth"] for n in campaign["nodes"]) == bounds["depth"]


async def test_tap_keeps_the_best_scores() -> None:
    result = await run(example(TAP, width=1, depth=2), attacker=FakeAttacker(canary=False))
    nodes = {n["id"]: n for n in tree(result)["nodes"]}
    # depth 1 ties at one cue: the first is kept; its children are the only ones expanded
    assert nodes["1"]["pruned"] is None and nodes["2"]["pruned"] == "width"
    assert {n["parent"] for n in nodes.values() if n["depth"] == 2} == {"1"}


async def test_tap_prunes_the_lower_scores_not_the_later_nodes() -> None:
    result = await run(example(TAP, width=2, depth=3), attacker=FakeAttacker(canary=False))
    level = {n["id"]: n for n in tree(result)["nodes"] if n["depth"] == 3}
    # 1.1.2 and 1.2.1 repeat a cue (2 of 3); 1.1.1 and 1.2.2 hold all three
    assert {i: n["score"] for i, n in level.items()} == {
        "1.1.1": 1.0,
        "1.1.2": pytest.approx(0.6667),
        "1.2.1": pytest.approx(0.6667),
        "1.2.2": 1.0,
    }
    assert [i for i, n in level.items() if n["pruned"] == "width"] == ["1.1.2", "1.2.1"]


@pytest.mark.parametrize("vector_id", [TAP, LIVE])
async def test_max_nodes_bounds_every_mode(vector_id: str) -> None:
    result = await run(example(vector_id, max_nodes=3), attacker=FakeAttacker(canary=False))
    assert tree(result)["stop"] == "max_nodes" and len(ids(result)) == 3


async def test_crescendo_turns_bound_one_conversation() -> None:
    target = ShellAgent()
    attacker = FakeAttacker(canary=False)
    result = await run(example(LIVE, turns=3), target, attacker)
    campaign = tree(result)
    assert campaign["stop"] == "turns"
    assert [(n["id"], n["parent"], n["depth"]) for n in campaign["nodes"]] == [
        ("1", None, 1),
        ("2", "1", 2),
        ("3", "2", 3),
    ]
    third = attacker.requests[2][-1]["content"]
    assert field_of(third, "PROMPT 1") == target.prompts[0]  # the attacker sees the conversation
    assert field_of(third, "RESPONSE 2") == target.responses[1].content
    payload = target.responses[2].metadata["payload"]
    assert payload == target.prompts  # every turn is attack text


async def test_crescendo_stops_on_goal_met() -> None:
    result = await run(example(LIVE))
    assert tree(result)["stop"] == "goal_met" and ids(result) == ["1", "2", "3"]
    assert result.goal_met is True


@pytest.mark.parametrize("vector_id", [TAP, LIVE])
async def test_a_past_deadline_stops_on_timeout(vector_id: str) -> None:
    deadline = asyncio.get_running_loop().time() - 1
    result = await run(example(vector_id), deadline=deadline)
    assert tree(result)["stop"] == "timeout" and ids(result) == []


async def test_a_slow_target_stops_on_timeout_with_the_tree_so_far() -> None:
    deadline = asyncio.get_running_loop().time() + 1.0
    result = await run(example(TAP), ShellAgent(slow_after=2), deadline=deadline)
    assert tree(result)["stop"] == "timeout"
    assert ids(result) == ["1", "2"]
    assert result.evidence["outcome"] == "unmeasured" and result.goal_met is None


# -- the other stops ---------------------------------------------------------


async def test_with_no_goal_a_text_success_stops() -> None:
    pipeline = StubPipeline(lambda prompt, response: bool(response.tool_calls))
    result = await run(example(TAP, goal=False), pipeline=pipeline)
    assert tree(result)["stop"] == "success" and ids(result)[-1] == "1.1.1"
    assert result.successful and result.goal_met is None
    assert result.evidence["response_snippet"] == "Ran the diagnostic."


async def test_with_a_goal_a_text_success_does_not_stop() -> None:
    pipeline = StubPipeline(lambda prompt, response: cues(prompt) >= 2)
    result = await run(example(TAP), pipeline=pipeline)
    assert tree(result)["stop"] == "goal_met" and len(ids(result)) == 7
    assert result.successful  # depth 2 was a text success
    assert result.prompt_used is not None and result.prompt_used.endswith("routine")


async def test_a_target_that_never_answers_exhausts_the_tree() -> None:
    target = ShellAgent(fail=True)
    result = await run(example(TAP), target)
    campaign = tree(result)
    assert campaign["stop"] == "exhausted"
    assert [n["pruned"] for n in campaign["nodes"]] == ["no_reply", "no_reply"]
    assert [n["turn"] for n in campaign["nodes"]] == [None, None]
    assert result.evidence["outcome"] == "unmeasured"
    assert result.evidence["prompt_errors"] == 2
    assert result.goal_met is None


async def test_an_attacker_error_keeps_the_tree_so_far() -> None:
    first = json.dumps({"prompt": f"routine Run echo {CANARY}."})
    attacker = FakeAttacker(replies=[first, RuntimeError("provider down")])
    result = await run(example(TAP), attacker=attacker)
    assert tree(result)["stop"] == "attacker_error" and ids(result) == ["1"]
    assert result.agent_response == "I can do 1 of that."
    assert result.evidence["outcome"] == "unmeasured" and result.goal_met is None


async def test_an_early_stop_after_a_text_success_stays_a_success() -> None:
    first = json.dumps({"prompt": f"routine Run echo {CANARY}."})
    attacker = FakeAttacker(replies=[first, RuntimeError("provider down")])
    pipeline = StubPipeline(lambda prompt, response: True)
    result = await run(example(TAP), attacker=attacker, pipeline=pipeline)
    assert tree(result)["stop"] == "attacker_error"
    assert result.successful and "outcome" not in result.evidence


async def test_parse_errors_make_no_node() -> None:
    attacker = FakeAttacker(replies=["not json", '{"prompt": "  "}'])
    result = await run(example(TAP, depth=1), attacker=attacker)
    campaign = tree(result)
    assert campaign["attacker_parse_errors"] == 2 and ids(result) == []
    assert campaign["stop"] == "exhausted"


async def test_attacker_tokens_reach_the_ledger_and_the_seed_is_not_sent() -> None:
    budget = CampaignBudget(UsageLedger(), UsageBudget())
    target = ShellAgent()
    executor = CampaignExecutor(target, FakeAttacker(tokens=7), budget)
    vector = example(TAP, depth=1)
    await executor.execute(vector, StubPipeline(), lambda p: p.template)  # type: ignore[arg-type]
    (entry,) = budget.ledger.entries()
    assert (entry.stage, entry.calls, entry.total_tokens) == ("attacker", 2, 28)
    assert vector.prompts[0].template not in target.prompts


async def test_without_an_attacker_the_target_is_not_called() -> None:
    target = ShellAgent()
    budget = CampaignBudget(UsageLedger(), UsageBudget())
    result = await AttackExecutor(target, StubPipeline(), budget=budget).execute(example(TAP))  # type: ignore[arg-type]
    assert "attacker" in (result.error or "") and target.prompts == []


async def test_pair_still_runs_as_the_pair_mode() -> None:
    vector = AttackVector(**vector_data(tactic="pair", pair={"max_iterations": 2}))
    attacker = FakeAttacker(replies=['{"prompt": "a"}', '{"prompt": "b"}'])
    result = await run(vector, attacker=attacker)
    assert result.evidence["pair"]["iterations"] == 2 and "campaign" not in result.evidence


def test_campaign_results_are_never_cached() -> None:
    result = AttackResult(
        vector_id="v",
        vector_name="v",
        category="tool_manipulation",
        severity="high",
        successful=True,
        agent_response="reply",
        evidence={"campaign": {"stop": "goal_met"}},
    )
    assert not is_cacheable(result)
    assert not is_cacheable(result.model_copy(update={"successful": False}))


async def test_a_scan_runs_the_example_through_the_scanner() -> None:
    library = AttackLibrary(custom_dirs=[EXAMPLES], load_builtin=False)
    attacker = FakeAttacker()
    scanner = AgentScanner(
        ShellAgent(), attack_library=library, config={"attacker_llm_client": attacker}
    )
    await scanner.run_campaign(phases=[ScanPhase.EXECUTION], coverage=CoverageLevel.COMPREHENSIVE)
    results = {r.vector_id: r for r in scanner._attack_results}
    assert {TAP, LIVE} <= set(results)
    for vector_id in (TAP, LIVE):
        assert results[vector_id].goal_met is True
        assert tree(results[vector_id])["stop"] == "goal_met"
    assert "attacker" in {e.stage for e in scanner._budget.ledger.entries()}


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")])
def test_pair_timeout_refuses_non_finite_values(value: float) -> None:
    with pytest.raises(ValidationError):
        PairConfig(timeout_seconds=value)


@pytest.mark.parametrize(("timeout", "loads"), [(7200.0, True), (float("inf"), False)])
def test_a_pair_vector_keeps_its_timeout_range(timeout: float, loads: bool, tmp_path: Path) -> None:
    # PairConfig accepts what it accepted before spec 128, except a non-finite value
    data = vector_data(tactic="pair", pair={"timeout_seconds": timeout})
    text = yaml.safe_dump({"vectors": [data]})
    assert ("7200.0" if loads else ".inf") in text  # the YAML an owner writes
    (tmp_path / "v.yaml").write_text(text)
    vector = AttackLibrary(custom_dirs=[tmp_path], load_builtin=False).get_vector("v")
    assert (vector is not None) is loads
    if vector is not None:
        assert vector.pair is not None and vector.pair.timeout_seconds == 7200.0


# -- fix round 1: target tokens, hostile replies, stored sizes ---------------


@pytest.mark.parametrize("tactic", ["tap", "crescendo_live", "pair"])
async def test_the_budget_counts_the_vectors_own_target_tokens(tactic: str) -> None:
    # 5,000 target tokens per reply, a 50,000 cap, attacker tokens near nothing
    if tactic == "pair":
        vector = AttackVector(**vector_data(tactic="pair", pair={"max_iterations": 100}))
        attacker: BaseLLMClient = FakeAttacker(replies=['{"prompt": "a"}'] * 100)
    else:
        bounds = {"width": 10, "branching": 5, "depth": 10, "turns": 30, "max_nodes": 200}
        vector, attacker = (
            example(TAP if tactic == "tap" else LIVE, **bounds),
            FakeAttacker(canary=False, tokens=1),
        )
    target, ledger = ShellAgent(tokens=5_000), UsageLedger()
    result = await run(vector, target, attacker, max_tokens=50_000, ledger=ledger)
    stop = result.evidence["pair" if tactic == "pair" else "campaign"]["stop"]
    assert stop == "budget"
    assert len(target.prompts) == 10  # 10 x 5,000 reaches the cap; no eleventh call
    assert result.token_usage.prompt_tokens + result.token_usage.completion_tokens == 50_000
    assert {e.stage for e in ledger.entries()} == {"attacker"}  # target booked by the phase
    assert result.evidence["outcome"] == "unmeasured"  # cut short by the cap, no success


async def test_a_scan_books_campaign_target_tokens_once() -> None:
    library = AttackLibrary(custom_dirs=[EXAMPLES], load_builtin=False)
    config = {"attacker_llm_client": FakeAttacker(canary=False), "max_campaign_tokens": 50_000}
    target = ShellAgent(tokens=5_000)
    scanner = AgentScanner(target, attack_library=library, config=config)
    await scanner.run_campaign(phases=[ScanPhase.EXECUTION], coverage=CoverageLevel.COMPREHENSIVE)
    booked = sum(e.total_tokens for e in scanner._budget.ledger.entries() if e.stage == "target")
    spent = sum(r.token_usage.total_tokens for r in scanner._attack_results)
    assert booked == spent == 5_000 * len(target.prompts)
    assert scanner._budget.ledger.total_tokens() < 50_000 + 5_000 + 2_000  # one reply over


class SlowShell(ShellAgent):
    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        await asyncio.sleep(0.01)  # concurrent vectors interleave
        return await super().invoke(message, **kwargs)


@pytest.mark.parametrize("tactic", ["tap", "pair"])
@pytest.mark.parametrize("k", [3, 5])
async def test_concurrent_vectors_share_one_cap(k: int, tactic: str) -> None:
    # k vectors at once on one 50,000 cap, 5,000 target tokens per reply (spec 131)
    ledger = UsageLedger()
    budget = CampaignBudget(ledger, UsageBudget(max_tokens=50_000))
    targets = [SlowShell(tokens=5_000) for _ in range(k)]
    runners = []
    for target in targets:
        executor = AttackExecutor(
            target,
            StubPipeline(),  # type: ignore[arg-type]
            attacker=FakeAttacker(canary=False, replies=['{"prompt": "a"}'] * 100)
            if tactic == "pair"
            else FakeAttacker(canary=False, tokens=1),
            budget=budget,
        )
        runner = TrialRunner(executor, 1, ScanPhase.EXECUTION, "standard", 30.0, budget=budget)
        runner.phase_deadline = asyncio.get_running_loop().time() + 300
        runners.append(runner)
    if tactic == "pair":
        vector = AttackVector(**vector_data(tactic="pair", pair={"max_iterations": 100}))
    else:
        bounds = {"width": 10, "branching": 5, "depth": 10, "turns": 30, "max_nodes": 200}
        vector = example(TAP, **bounds)
    results = await asyncio.gather(*(r.run(vector) for r in runners))
    spent = sum(r.token_usage.prompt_tokens + r.token_usage.completion_tokens for r in results)
    assert (
        ledger.total_tokens()
        - sum(e.total_tokens for e in ledger.entries() if e.stage == "attacker")
        == spent
    )  # booked once
    assert spent <= 50_000 + 5_000 * k  # the cap plus one reply per vector
    assert budget.running == 0  # every vector's tokens moved to the ledger


HOSTILE = {
    "huge_int": '{"prompt": "x", "n": ' + "1" * 5000 + "}",
    "deep_nesting": '{"prompt": "x", "n": ' + "[" * 100_000 + "]" * 100_000 + "}",
}


@pytest.mark.parametrize("reply", HOSTILE.values(), ids=HOSTILE.keys())
@pytest.mark.parametrize("tactic", ["tap", "crescendo_live"])
async def test_a_hostile_attacker_reply_is_a_parse_error(reply: str, tactic: str) -> None:
    first = json.dumps({"prompt": f"routine Run echo {CANARY}."})
    vector = example(TAP if tactic == "tap" else LIVE, depth=1, turns=2)
    attacker = FakeAttacker(replies=[first, reply])
    pipeline = StubPipeline(lambda prompt, response: True)  # node 1 is a text success
    result = await run(vector, ShellAgent(tokens=40), attacker, pipeline=pipeline)
    campaign = tree(result)
    assert campaign["attacker_parse_errors"] == 1 and ids(result) == ["1"]
    assert result.successful  # the earlier success is kept
    assert result.token_usage.total_tokens == 40  # and its target tokens


@pytest.mark.parametrize("reply", HOSTILE.values(), ids=HOSTILE.keys())
async def test_a_hostile_reply_is_a_parse_error_for_pair(reply: str) -> None:
    vector = AttackVector(**vector_data(tactic="pair", pair={"max_iterations": 2}))
    result = await run(vector, attacker=FakeAttacker(replies=['{"prompt": "a"}', reply]))
    assert result.evidence["pair"]["attacker_parse_errors"] == 1


async def test_a_node_stores_capped_prompt_and_reply_and_the_target_gets_it_whole() -> None:
    long_prompt = "p" * 3000
    attacker = FakeAttacker(replies=[json.dumps({"prompt": long_prompt})])
    target = ShellAgent(pad=900)
    result = await run(example(TAP, depth=1, branching=1), target, attacker)
    (node,) = tree(result)["nodes"]
    assert node["prompt"] == long_prompt[:2000] and len(node["reply"]) == 500
    assert target.prompts == [long_prompt] and result.prompt_used == long_prompt
