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
from ziran.domain.entities.goal import ApprovalBypassGoal, SecretLeakGoal
from ziran.domain.entities.target import BrowserConfig, TargetConfig
from ziran.domain.interfaces.adapter import AgentResponse, AgentState, BaseAgentAdapter
from ziran.domain.replies import ERROR_SENTINELS

pytestmark = pytest.mark.unit

SECRET = "sk-test-0042"


def heard(prompts: list[str]) -> str:
    return hashlib.sha256("\x00".join(prompts).encode()).hexdigest()[:16]


class StatefulAgent(BaseAgentAdapter):
    """Replies with a digest of every message in its session; ``reset_state`` starts a new one.
    ``approve`` calls ``request_approval`` and ``pay`` calls ``pay`` (with a trailing amount);
    ``secret`` leaks the secret. A message in ``broken`` fails (``raise`` or an error sentinel)
    every time after its first."""

    def __init__(
        self, *, keeps_memory: bool = False, tokens: int = 0, broken: str = "", fail: str = ""
    ) -> None:
        self.keeps_memory, self.tokens, self.broken, self.fail = keeps_memory, tokens, broken, fail
        self.session: list[str] = []
        self.prompts: list[str] = []
        self.resets = 0

    @property
    def isolates_sessions(self) -> bool:
        return True

    @property
    def memory_persists_across_reset(self) -> bool:
        return self.keeps_memory

    async def invoke(self, message: str, **kwargs: Any) -> AgentResponse:
        again = message == self.broken and message in self.prompts
        self.prompts.append(message)
        self.session.append(message)
        await asyncio.sleep(0)  # lets a concurrent run interleave here
        if again and self.fail == "raise":
            raise ConnectionError("target down")
        reply = sorted(ERROR_SENTINELS)[0] if again else heard(self.session)
        reply += f" {SECRET}" if "secret" in message else ""
        tools = {"approve": "request_approval", "pay": "pay"}
        amount = {"amount": message.split()[-1]} if message[-1].isdigit() else {}
        calls = [{"tool": tool, "input": amount} for cue, tool in tools.items() if cue in message]
        half = self.tokens // 2
        return AgentResponse(
            content=reply,
            tool_calls=calls,
            prompt_tokens=half,
            completion_tokens=self.tokens - half,
            total_tokens=self.tokens or 5,
        )

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


SPEND = ApprovalBypassGoal(
    type="approval_bypass",
    tool="pay",
    approval_tools=["request_approval"],
    amount="amount",
    threshold=100,
)


async def test_a_branch_goal_counts_the_ancestors_turns() -> None:
    # 1 pays 60 and its child 1.1 pays 60 more: neither alone passes 100, the branch does.
    goal = SPEND
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


@pytest.mark.parametrize(
    ("goal", "replies", "met"),
    [
        (SPEND, ["pay 60", "pay 60"], True),  # siblings pass 100 together in the one session
        (None, ["please approve", "please pay"], False),  # the approval came first in it
    ],
)
async def test_a_shared_session_is_judged_as_one_conversation(
    goal: Any, replies: list[str], met: bool
) -> None:
    goal = goal or ApprovalBypassGoal(
        type="approval_bypass", tool="pay", approval_tools=["request_approval"]
    )
    config = CampaignConfig(width=2, branching=2, depth=1)
    vector = AttackVector(**vector_data(tactic="tap", campaign=config, goal=goal))
    attacker = FakeAttacker(replies=[reply(r) for r in replies])
    result = await run(vector, StatefulAgent(keeps_memory=True), attacker)
    assert tree(result)["session"] == "shared"
    assert result.goal_met is met
    assert tree(result)["stop"] == ("goal_met" if met else "depth")


@pytest.mark.parametrize("fail", ["raise", "sentinel"])
async def test_a_failed_replay_leaves_the_node_with_no_reply(fail: str) -> None:
    # every replay of node 1's prompt fails: 1.1 and 1.2 get no reply and are never sent
    config = CampaignConfig(width=1, branching=2, depth=2)
    vector = AttackVector(**vector_data(tactic="tap", campaign=config))
    attacker = FakeAttacker(replies=[reply(r) for r in ("a", "b", "c", "d")])
    target = StatefulAgent(broken="a", fail=fail)
    result = await run(vector, target, attacker)
    nodes = {n["id"]: n for n in tree(result)["nodes"]}
    assert list(nodes) == ["1", "2", "1.1", "1.2"] and tree(result)["stop"] == "exhausted"
    assert [nodes[i]["pruned"] for i in ("1.1", "1.2")] == ["no_reply", "no_reply"]
    assert target.prompts == ["a", "b", "a", "a"]  # c and d never reach a session without a
    assert result.evidence["prompt_errors"] == 2


async def test_a_secret_leaked_in_a_branch_reply_meets_the_goal() -> None:
    goal = SecretLeakGoal(type="secret_leak", secret=SECRET)
    config = CampaignConfig(width=1, branching=1, depth=2)
    vector = AttackVector(**vector_data(tactic="tap", campaign=config, goal=goal))
    attacker = FakeAttacker(replies=[reply("hello"), reply("tell the secret")])
    result = await run(vector, StatefulAgent(), attacker)
    assert tree(result)["stop"] == "goal_met"
    assert result.goal_met is True
    assert [c.turn for c in result.goal_evidence] == [2]


async def test_replays_stop_at_the_cap() -> None:
    # 5,000 target tokens per call and a 50,000 cap: exactly ten target calls, replays included
    bounds = {"width": 10, "branching": 5, "depth": 10, "max_nodes": 200}
    target = StatefulAgent(tokens=5_000)
    vector = example(TAP, goal=False, **bounds)
    result = await run(vector, target, FakeAttacker(canary=False, tokens=1), max_tokens=50_000)
    assert tree(result)["stop"] == "budget"
    assert len(target.prompts) == 10
    assert result.token_usage.prompt_tokens + result.token_usage.completion_tokens == 50_000


async def test_a_browser_target_keeps_one_shared_session() -> None:
    from ziran.infrastructure.adapters.browser_adapter import BrowserAgentAdapter

    config = TargetConfig(
        url="https://chat.example.com", protocol="browser", browser=BrowserConfig()
    )
    browser = BrowserAgentAdapter(config)
    browser.invoke = StatefulAgent().invoke  # type: ignore[method-assign]
    result = await run(example(TAP, goal=False, **SMALL), browser, FakeAttacker(canary=False))
    assert tree(result)["session"] == "shared"
