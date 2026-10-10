# Feature Specification: map RAG-agent tool names to existing chain capabilities

**Feature Branch**: `ziran-rag-mapping`
**Created**: 2026-10-10
**Status**: Active
**Track**: SLICE (no contract, schema, pattern or infrastructure change; under ten tasks)
**Base**: `develop` @ b813e4f
**Input**: an agent whose tools are named `recursive_url_loader`, `tavily_search` and
`vector_store_query` gets zero dangerous chains from `ToolChainAnalyzer`. No chain pattern side
recognises these names, and `canonical_tool_name` leaves them unchanged. Map them (and the close
variants a reader would expect) to capabilities the patterns already use, so the existing chain
patterns can fire on agents that use them.

## Current behaviour (read on `develop` @ b813e4f)

- `ToolChainAnalyzer` (`ziran/application/knowledge_graph/chain_analyzer.py`) resolves every
  tool or capability node id with `canonical_tool_name` (lines 217-218, 457-458), then matches
  each `(source, target)` pattern from `chain_patterns.yaml` by substring or keyword overlap.
- `canonical_tool_name` (`ziran/application/knowledge_graph/tool_aliases.py`) maps Claude Code
  ids only (`Read`, `WebFetch`, `WebSearch`, `mcp__...`, `Name(spec)`); every other id is
  returned unchanged.
- The LangChain adapter gives capability nodes the id `tool_<name>`
  (`ziran/infrastructure/adapters/langchain_adapter.py:47`), so the analyzer sees
  `tool_tavily_search`, not `tavily_search`.
- Checked with the default pattern registry (124 patterns): none of the three names, with or
  without the `tool_` prefix, matches any pattern source or target. `vector_store_query` misses
  `vector_store_read` because the keyword `query` does not overlap `read`.
- The patterns already hold the capabilities these tools have: `http_request` (outbound fetch,
  source of remote-content and RAG-ingest chains, target of exfiltration chains), `browse_url`
  (web content as a source) and `vector_store_read` (target of `rag_poisoning`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - RAG-agent tool names resolve to existing capabilities (Priority: P1)

A user scans a LangChain RAG agent. Its loader, search and vector store tools take part in the
chain patterns that already describe those capabilities.

**Independent Test**: `canonical_tool_name` on each name returns the expected keyword.

**Acceptance Scenarios**:
1. `canonical_tool_name("recursive_url_loader") == "http_request"`.
2. `canonical_tool_name("tavily_search") == "browse_url"`.
3. `canonical_tool_name("vector_store_query") == "vector_store_read"`.
4. The LangChain adapter id form (`tool_recursive_url_loader`, `tool_tavily_search`,
   `tool_vector_store_query`) resolves the same way.
5. The variants under Assumptions resolve the same way.

### User Story 2 - Existing chain patterns fire on those tools (Priority: P1)

**Independent Test**: build an in-memory `AttackKnowledgeGraph` with two tool nodes and a
`CAN_CHAIN_TO` edge, run `ToolChainAnalyzer.analyze()`.

**Acceptance Scenarios** (ids in the LangChain adapter form `tool_<name>`):
1. `tool_recursive_url_loader -> tool_execute_code` gives `remote_code_execution` (critical).
2. `tool_recursive_url_loader -> tool_vector_store_write` gives `external_rag_poisoning` (high).
3. `tool_read_file -> tool_recursive_url_loader` gives `data_exfiltration` (critical).
4. `tool_tavily_search -> tool_execute_code` gives `web_content_to_rce` (critical).
5. `tool_vector_store_write -> tool_vector_store_query` gives `rag_poisoning` (high).
6. Reported chains keep the original tool ids in `tools` and `graph_path`.

### User Story 3 - Nothing else changes (Priority: P1)

**Acceptance Scenarios**:
1. Every existing `canonical_tool_name` case keeps its result: Claude Code built-ins, rule forms
   and MCP outbound tools win over the new map, and ids such as `read`, `bash`,
   `tool_http_request` and `harmless_a` stay unchanged.
2. Ids that only share a word with the new names stay unchanged: `search`, `web_search`,
   `vector_store_write`, `url_loader`.
3. Ids that contain a name next to other words keep their own words and chains:
   `shell_execute_tavily_search`, `tavily_search_and_send_email`, `vectorstore_search_database`,
   `vector_store_query_writer`, `save_vectors_to_research_db`, `recursive_url_loader_write_file`
   and `Foo(tavily_search)` stay unchanged. `Agent -> shell_execute_tavily_search` still gives
   `delegation_to_rce` (critical) and `tool_read_file -> send_email_tavily_search` still gives
   `data_exfiltration` (critical).
4. No chain pattern, pattern YAML, classifier entry, node, edge type or output field changes.

### Edge Cases

- **Anchored match after squashing**: the id is lowercased and every non-alphanumeric
  character is removed. What is left must equal a key, with
  an optional `tool` prefix and an optional `results`, `json` or `resultsjson` suffix. The alias
  replaces the whole id, so a looser substring match would drop the id's other words: a tool
  named `shell_execute_tavily_search` would lose its `shell_execute` chains. An id with any other
  word around the name is left unchanged and matches the patterns on its own words.
- **MCP ids are deliberately not mapped**: an `mcp__<server>__<tool>` id keeps the existing MCP
  outbound rule and is otherwise left unchanged, as before this change. The server name can
  carry capability words: `mcp__send_email__tavily_search` matches the `send_email` patterns
  by substring, and mapping it to `browse_url` would drop its `data_exfiltration` chain. So
  `mcp__tavily__tavily_search` is not mapped either.
- **A graph with only these three tools** forms no chain: no existing pattern links
  `http_request` or `browse_url` to `vector_store_read`. Chains fire when the agent also has a
  tool on the other side of a pattern (code execution, file write, vector store write, file
  read). Adding a pattern is out of scope.
- **Risk tier** (`ziran/domain/tool_classifier.py`) is not changed: it does not feed chain
  matching, and `WebFetch` / `WebSearch` are not classified dangerous either.
- **Scope is naming only.** The item maps names. It does not make an agent with these tools
  report a chain it has no tool for: an expected `rag_poisoning` finding still needs a
  vector store write tool on the agent.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `canonical_tool_name` maps the three names and their variants to `http_request`,
  `browse_url` and `vector_store_read` (US1).
- **FR-002**: the mapping applies only when the Claude Code rules do not: built-in names, rule
  forms and MCP outbound verbs keep precedence (US3.1).
- **FR-003**: no change to `chain_patterns.yaml`, `ChainPatternRegistry`, `ToolChainAnalyzer`,
  the tool classifier, adapters or any output shape (US3.4).
- **FR-004**: `docs/concepts/tool-chains.md` lists the new names next to the Claude Code table.
- **FR-005**: no new dependency; `uv.lock` unchanged.

### Assumptions

- **Capability choice.** `recursive_url_loader` fetches pages from a URL over HTTP and follows
  links: `http_request`, as `WebFetch` already maps. `tavily_search` runs a web search and
  returns untrusted web content: `browse_url`, as `WebSearch` already maps.
  `vector_store_query` reads stored documents back from a vector store: `vector_store_read`, the
  read side of `rag_poisoning`. Why: each is the pattern keyword that names the tool's own
  capability, and two follow an existing alias. Overturn: if `tavily_search` should match the
  `serpapi -> send_email` search pattern, or `vector_store_query` the `database_query` patterns;
  `canonical_tool_name` returns one keyword, so either swap loses the current matches.
- **Variants.** `recursive_url_loader`: `RecursiveUrlLoader` (the LangChain loader class name),
  `recursive-url-loader`. `tavily_search`: `TavilySearch`, `tavily_search_results`,
  `tavily_search_results_json` (LangChain's `TavilySearchResults` default tool name),
  `TavilySearchResults`.
  `vector_store_query`: `vectorstore_query`, `VectorStoreQuery`, `vector_store_search`,
  `vectorstore_search`. Each also with the `tool_` prefix the LangChain adapter adds.
  Matching is anchored (see Edge Cases): the squashed id, after that prefix, must equal a key
  or a key plus `results`, `json` or `resultsjson`. MCP-prefixed forms
  (`mcp__<server>__<name>`) are deliberately not mapped, because the server name can carry
  capability words that the alias would drop. Why: these are the spellings a reader would
  expect for the same tool, and an anchored match never drops the words of an id that only
  contains a name. Overturn: a common real tool id with another wrapper word (for example a
  `_tool` suffix) that should map but does not, or a need to map MCP RAG tools that a
  server-word check can make safe.
- **Not mapped**: generic names such as `search`, `web_search`, `retriever` or
  `similarity_search`. They do not name these tools, and broad names would change matching for
  unrelated agents. `TavilySearchAPIWrapper` and `TavilySearchAPIRetriever` are LangChain
  helper classes, not tool names, and stay unmapped.
- **Placement.** The map sits in `tool_aliases.py`, the single alias map the analyzer and trace
  analysis already share. The module docstring is widened from "Claude Code" to "Claude Code and
  LangChain-style" ids. Overturn: if a reviewer wants framework aliases in their own module.

## Success Criteria *(mandatory)*

- **SC-001**: the US1 and US2 tests fail on b813e4f and pass after the change.
- **SC-002**: every existing test case passes; no existing case is changed or removed (new
  cases are added to the existing parametrized list).
- **SC-003**: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy ziran/` and
  `uv run pytest --cov=ziran` (coverage at least 85%) pass.

## Clarifications

### Session 2026-10-10

- Q: Alias map or tool classifier? A: alias map. Chain matching reads `canonical_tool_name`;
  the classifier gives risk tiers and is not read by the analyzer.
- Q: Exact names only? A: no, but anchored. LangChain capability ids carry a `tool_` prefix,
  so exact matching would miss the adapter's own ids. Match the squashed id after an optional
  `tool` prefix, with an optional `results`/`json` suffix, and nothing else (see Edge Cases).
  MCP ids are not mapped, since their server name can carry capability words. A substring match was rejected: the alias replaces the whole id, so an
  id such as `shell_execute_tavily_search` would lose its `delegation_to_rce` chain.
- Q: Add a pattern so the three tools chain with each other? A: no, out of scope; the item
  maps names to existing capabilities only.
