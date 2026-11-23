# Feature Specification: read LangChain agent output given as content blocks

**Feature Branch**: `fix/090-langchain-block-output`
**Created**: 2026-11-23
**Status**: Active
**Plan item**: A-LC-ANTHROPIC-OUTPUT (goal G-a).
**Base**: `develop` @ d1fa050.

## The promise in our own words

`LangChainAdapter.invoke` treats `result["output"]` as a string. With a chat model that answers in
content blocks (Anthropic's, for one), the output is a list such as
`[{"type": "text", "text": "hi"}, {"type": "tool_use", ...}]`. The adapter then calls `.strip()`
on that list in `_is_iteration_limit_response`, the call raises, `AttackExecutor` logs
`prompt_error`, and the vector records no measured reply. A scan of such an agent measures no
vector.

The adapter now turns the output into text first. A string stays as it is. A list keeps the text
of its text blocks, in order, joined with no separator: a dict with `type == "text"`, an object
with `type == "text"` and a string `.text`, or a bare string item. Other blocks (tool use, images)
are dropped. Everything after that (history, the iteration-limit check, `AgentResponse.content`)
reads the text. `AttackExecutor` is unchanged: a vector whose adapter raises still logs
`prompt_error` as before.

The other in-process adapters were checked with one grep for the same assumption: LangGraph
reads `AIMessage.text` (which already joins text blocks), CrewAI and OpenAI Agents call `str()`,
AutoGen calls `to_text()`. None of them assumes a string, so the helper stays private to the
LangChain adapter.

## Acceptance scenarios

1. Given a LangChain agent whose AgentExecutor returns
   `[{"type": "text", "text": "hi"}, {"type": "tool_use", ...}]`, when `LangChainAdapter.invoke`
   runs, then `AgentResponse.content` is `"hi"` and nothing raises.
2. Given that agent and one attack vector, when `AttackExecutor` runs it, then the vector yields
   an `AttackResult` scored by the detectors, with no `prompt_errors` count (so no `prompt_error`
   was logged).
3. Given a string output, when `invoke` runs, then the behaviour equals the base branch.

## Assumptions

- Text blocks join with no separator (the extra is not installed here, so the match with
  langchain-core `BaseMessage.text` is unchecked). Overturned if
  a model splits words across blocks in a way that needs a space.
- A non-list, non-string output becomes `str(output)` instead of raising. The base raised on it;
  no known agent returns one.
