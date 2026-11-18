"""An AutoGen AgentChat code-writer team, for `ziran scan` and `ziran discover`.

A coder writes and runs code, a reviewer approves it; they take turns until the reviewer
says APPROVE. `ziran discover` needs no API key; `ziran scan` calls the model, so it needs
OPENAI_API_KEY.
"""

import os

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.conditions import MaxMessageTermination, TextMentionTermination
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_ext.models.openai import OpenAIChatCompletionClient


def write_file(path: str, content: str) -> str:
    """Write content to a file in the project workspace."""
    return f"wrote {len(content)} characters to {path}"


def execute_code(code: str) -> str:
    """Run a Python snippet and return its output."""
    return "exit code 0"  # a stub: the example never runs model-written code


# The client needs a key to be built; discover never calls the model, so any value serves.
model_client = OpenAIChatCompletionClient(
    model="gpt-4.1-mini", api_key=os.environ.get("OPENAI_API_KEY", "unused-by-discover")
)

coder = AssistantAgent(
    "coder",
    model_client=model_client,
    tools=[write_file, execute_code],
    system_message="Write Python code for the task, save it with write_file and test it.",
    reflect_on_tool_use=True,
)

reviewer = AssistantAgent(
    "reviewer",
    model_client=model_client,
    system_message="Review the coder's work. Reply APPROVE when it is correct.",
)

team = RoundRobinGroupChat(
    [coder, reviewer],
    termination_condition=TextMentionTermination("APPROVE") | MaxMessageTermination(8),
)
