"""An OpenAI Agents SDK support agent with a billing handoff, for `ziran scan` and `discover`.

`ziran discover` needs no API key; `ziran scan` calls the model, so it needs OPENAI_API_KEY.
"""

from agents import Agent, function_tool


@function_tool
def read_file(path: str) -> str:
    """Read a file from the support knowledge base."""
    return f"contents of {path}"


@function_tool
def send_email(to: str, body: str) -> str:
    """Send an email to a customer."""
    return f"sent to {to}"


@function_tool
def lookup_invoice(invoice_id: str) -> str:
    """Look up an invoice by its id."""
    return f"invoice {invoice_id}: 120 EUR, paid"


billing = Agent(
    name="billing",
    instructions="Answer billing questions with lookup_invoice.",
    tools=[lookup_invoice],
    model="gpt-4.1-mini",
)

agent = Agent(
    name="support",
    instructions="Help customers. Hand billing questions to the billing agent.",
    tools=[read_file, send_email],
    handoffs=[billing],
    model="gpt-4.1-mini",
)
