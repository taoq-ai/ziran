"""Unit tests: the action verb of a tool's own name types it (spec 099, change 1 with A1 and A2).

Every tool name here is made up. None is taken from a benchmark's tool list.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from ziran.application.detectors.provenance import is_state_changing
from ziran.application.hybrid.jobs import classify_tools
from ziran.application.knowledge_graph.role_typing import tool_roles
from ziran.infrastructure.llm.base import LLMResponse
from ziran.infrastructure.llm.replay_client import RecordReplayClient

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit

READER, ACTOR = frozenset({"source"}), frozenset({"high_impact"})
FIELDS = ("reads_untrusted", "reads_private", "egress", "exec", "high_impact")


class TestTheVerbRule:
    def test_a_read_verb_first_makes_a_reader(self) -> None:
        assert tool_roles("lookup_ticket") == READER

    def test_a_write_verb_first_makes_an_actor_with_the_role_its_verb_names(self) -> None:
        assert tool_roles("publish_bulletin") == {"egress"}
        assert tool_roles("execute_job") == {"exec"}
        assert tool_roles("delete_account") == {"high_impact"}
        assert tool_roles("transfer_funds") == {"egress", "high_impact"}
        assert tool_roles("reserve_hotel") == ACTOR  # a write verb that names no sink role

    def test_a_name_with_no_listed_verb_is_an_actor(self) -> None:
        assert tool_roles("acme_gateway") == ACTOR

    def test_a_sink_noun_after_a_read_verb_does_not_decide(self) -> None:
        assert tool_roles("get_message") == READER
        assert tool_roles("list_email_folders") == READER

    def test_the_first_listed_verb_decides_not_the_last(self) -> None:
        assert tool_roles("find_and_delete") == READER
        assert tool_roles("delete_and_list") == ACTOR

    def test_a_blank_id_has_no_role(self) -> None:
        assert tool_roles("") == frozenset()

    def test_a_table_tool_keeps_its_roles(self) -> None:
        assert tool_roles("Read") == READER  # read_file
        assert tool_roles("Bash") == {"exec"}  # shell_execute
        assert tool_roles("WebFetch") == {"egress"}  # http_request: no verb, the table's words
        assert tool_roles("WebFetch", frozenset()) == {"egress"}

    def test_a_role_from_a_usable_reply_is_never_overruled(self) -> None:
        assert tool_roles("lookup_ticket", frozenset({"egress"})) == {"egress"}

    def test_a_reply_that_gives_no_role_takes_the_verb_rule(self) -> None:
        assert tool_roles("lookup_ticket", frozenset()) == READER
        assert tool_roles("acme_gateway", frozenset()) == ACTOR


class TestTheOwnName:
    def test_an_mcp_reader_is_a_source(self) -> None:
        assert "source" in tool_roles("mcp__x__describe_table")

    def test_a_server_word_does_not_type_the_tool(self) -> None:
        assert tool_roles("mcp__email__list_folders") == READER
        assert tool_roles("mcp__shell__list_sessions") == READER

    def test_a_toolkit_word_that_is_a_write_verb_does_not_decide(self) -> None:
        assert tool_roles("AcmeCallListRecent", toolkit="AcmeCall") == READER
        assert tool_roles("AcmeCallDial", toolkit="AcmeCall") == ACTOR
        assert tool_roles("AcmeTextSearch", toolkit="AcmeText") == READER

    def test_a_noun_after_the_verb_that_is_also_a_write_verb_does_not_decide(self) -> None:
        assert tool_roles("AcmeMailReadEmail", toolkit="AcmeMail") == READER

    def test_without_the_toolkit_the_whole_id_is_the_own_name(self) -> None:
        assert tool_roles("AcmeCallListRecent") == ACTOR  # `call` is the first listed verb

    def test_a_toolkit_the_id_does_not_start_with_is_ignored(self) -> None:
        assert tool_roles("lookup_ticket", toolkit="Acme") == READER


# study-v2's values (8e00758): the trace path's rule must not move with role typing (B1, B2)
STATE_CHANGING_AT_STUDY_V2 = {
    "get_balance": False,
    "send_money": True,
    "mcp__x__describe_table": False,
    "mcp__email__list_folders": True,
    "AcmeCallListRecent": True,
    "AcmeCallDial": True,
    "AcmeTextSearch": True,
    "AcmeMailReadEmail": True,
    "read_file": False,
    "Bash": True,
    "shell_execute": True,
    "update_record": True,
    "acme_gateway": False,
    "listAndDelete": False,
    "deleteAndList": True,
    "": False,
    "open_door": False,
    "schedule_transaction": True,
}


def test_is_state_changing_keeps_its_study_v2_values() -> None:
    assert {n: is_state_changing(n) for n in STATE_CHANGING_AT_STUDY_V2} == (
        STATE_CHANGING_AT_STUDY_V2
    )


# ── A2: one fallback, whatever the reason a tool has no model role ───

TOOLS = ["acme_gateway", "get_message", "set_signal"]


async def _roles(tmp_path: Path, reply: list[dict[str, object]]) -> dict[str, frozenset[str]]:
    class _Raw(RecordReplayClient):
        async def complete(self, messages: list[dict[str, str]], **kwargs: object) -> LLMResponse:
            return LLMResponse(content=json.dumps({"tools": reply}))

    client = _Raw("m", "c 1.0", record_to=tmp_path / "x.requests.jsonl")
    overrides, _ = await classify_tools(TOOLS, client, share=1.0)
    return {t: tool_roles(t, overrides.get(t)) for t in TOOLS}


def _no(n: int) -> dict[str, object]:
    return {"tool": n, **dict.fromkeys(FIELDS, "no")}


@pytest.mark.parametrize(
    "unusable",
    [[_no(1), _no(2)], [_no(1), _no(3), _no(2)]],
    ids=["wrong_count", "numbers_out_of_order"],
)
async def test_an_unusable_reply_types_a_tool_as_a_reply_of_no_on_every_field(
    tmp_path: Path, unusable: list[dict[str, object]]
) -> None:
    answered_no = await _roles(tmp_path, [_no(1), _no(2), _no(3)])
    assert await _roles(tmp_path, unusable) == answered_no
    assert answered_no == {"acme_gateway": ACTOR, "get_message": READER, "set_signal": ACTOR}
