"""TAP session isolation (spec 133): each node replays its branch in a fresh target session
where a reset gives one, and goals are judged per branch. Offline: a stateful scripted agent."""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import pytest

from tests.unit.test_campaign_executor import (
    TAP,
    FakeAttacker,
    StubPipeline,
    example,
    run,
    tree,
    vector_data,
)
from ziran.application.attacks.tactics import TacticExecutor
from ziran.domain.entities.attack import AttackPrompt, AttackVector, CampaignConfig
from ziran.domain.entities.goal import ApprovalBypassGoal
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter

pytestmark = pytest.mark.unit


def heard(prompts: list[str]) -> str:
    return hashlib.sha256("\x00".join(prompts).encode()).hexdigest()[:16]


class StatefulAgent(BaseAgentAdapter):
    """Replies with a digest of every message in its session; ``reset_state`` starts a new one.
    ``approve`` calls ``request_approval`` and ``pay`` calls ``pay`` (with a trailing amount)."""

    def __init__(self, *, keeps_memory: bool = False) -> None:
        self.keeps_memory = keeps_memory
        self.session: list[str] = []
        self.prompts: list[str] = []
        self.resets = 0

    @property
    def memory_persists_across_reset(self) -> bool:
        return self.keeps_memory

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        self.prompts.append(message)
        self.session.append(message)
        await asyncio.sleep(0)  # lets a concurrent run interleave here
        reply = heard(self.session)
        tools = {"approve": "request_approval", "pay": "pay"}
        amount = {"amount": message.split()[-1]} if message[-1].isdigit() else {}
        calls = [{"tool": tool, "input": amount} for cue, tool in tools.items() if cue in message]
        return AgentResponse(content=reply, tool_calls=calls, total_tokens=5)

    async def discover_capabilities(self) -> list[Any]:
        return []

    def get_state(self) -> AgentState:
        return AgentState(session_id="stateful")

    def reset_state(self) -> None:
        self.resets += 1
        if not self.keeps_memory:
            self.session = []

    def observe_tool_call(self, tool_name: str, inputs: dict[str, Any], outputs: Any) -> None:
        return None


def branches(result: Any) -> dict[str, list[str]]:
    """Each node's branch prompts: its ancestors' prompts, then its own."""
    nodes = {n["id"]: n for n in tree(result)["nodes"]}
    out: dict[str, list[str]] = {}
    for node_id, node in nodes.items():
        chain, at = [], node
        while at is not None:
            chain.insert(0, at["prompt"])
            at = nodes.get(at["parent"]) if at["parent"] else None
        out[node_id] = chain
    return out


SMALL = {"width": 2, "branching": 2, "depth": 3, "max_nodes": 24}


async def test_acceptance_each_node_reply_depends_only_on_its_branch() -> None:
    target = StatefulAgent()
    result = await run(example(TAP, goal=False, **SMALL), target, FakeAttacker(canary=False))
    campaign = tree(result)
    assert campaign["session"] == "isolated"
    nodes = {n["id"]: n for n in campaign["nodes"]}
    assert len(nodes) == 2 + 4 + 4 and campaign["stop"] == "depth"
    for node_id, chain in branches(result).items():
        assert nodes[node_id]["reply"] == heard(chain), node_id
    assert target.resets == len(nodes)  # one fresh session per node
    assert len(target.prompts) == sum(n["depth"] for n in nodes.values())  # replays its branch
    assert result.token_usage.total_tokens == 5 * len(target.prompts)  # replays are booked


async def test_a_target_that_keeps_memory_across_reset_shares_one_session() -> None:
    target = StatefulAgent(keeps_memory=True)
    result = await run(example(TAP, goal=False, **SMALL), target, FakeAttacker(canary=False))
    campaign = tree(result)
    assert campaign["session"] == "shared"
    assert target.resets == 0
    nodes = campaign["nodes"]
    assert len(target.prompts) == len(nodes)  # no replay
    assert nodes[1]["reply"] == heard([nodes[0]["prompt"], nodes[1]["prompt"]])  # pooled


def reply(prompt: str) -> str:
    return json.dumps({"improvement": "x", "prompt": prompt})


async def test_a_goal_is_judged_on_its_branch_not_pooled_across_siblings() -> None:
    # Node 1 asks for approval, its sibling 2 pays: pooled, the approval came first and the
    # goal is not met; on branch 2 alone the payment had no approval, so the goal is met there.
    goal = ApprovalBypassGoal(
        type="approval_bypass", tool="pay", approval_tools=["request_approval"]
    )
    config = CampaignConfig(width=2, branching=2, depth=1)
    vector = AttackVector(**vector_data(tactic="tap", campaign=config, goal=goal))
    attacker = FakeAttacker(replies=[reply("please approve"), reply("please pay")])
    result = await run(vector, StatefulAgent(), attacker)
    assert tree(result)["stop"] == "goal_met"
    assert result.goal_met is True
    assert [(c.turn, c.tool) for c in result.goal_evidence] == [(2, "pay")]  # node 2's turn only


async def test_a_branch_goal_counts_the_ancestors_turns() -> None:
    # 1 pays 60 and its child 1.1 pays 60 more: neither alone passes 100, the branch does.
    goal = ApprovalBypassGoal(
        type="approval_bypass",
        tool="pay",
        approval_tools=["request_approval"],
        amount="amount",
        threshold=100,
    )
    config = CampaignConfig(width=1, branching=1, depth=2)
    vector = AttackVector(**vector_data(tactic="tap", campaign=config, goal=goal))
    attacker = FakeAttacker(replies=[reply("pay 60"), reply("pay 60")])
    result = await run(vector, StatefulAgent(), attacker)
    assert tree(result)["stop"] == "goal_met"
    assert [c.turn for c in result.goal_evidence] == [1, 2]


async def test_a_node_reset_never_cuts_a_concurrent_multi_turn_conversation() -> None:
    target = StatefulAgent()
    talk = ["one", "two", "three", "four"]
    crescendo = AttackVector(
        **vector_data(tactic="crescendo", prompts=[AttackPrompt(template=t) for t in talk])
    )
    replies: dict[int, str] = {}
    tactic = TacticExecutor(target).execute(
        crescendo,
        StubPipeline(),  # type: ignore[arg-type]
        lambda p: p.template,
        replies=replies,
    )
    tap = run(example(TAP, goal=False, **SMALL), target, FakeAttacker(canary=False))
    _, result = await asyncio.gather(tactic, tap)
    assert replies == {i: heard(talk[:i]) for i in range(1, 5)}  # one uncut session
    nodes = {n["id"]: n for n in tree(result)["nodes"]}
    for node_id, chain in branches(result).items():
        assert nodes[node_id]["reply"] == heard(chain), node_id
