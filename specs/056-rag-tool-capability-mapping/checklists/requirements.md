# Requirements checklist: map RAG-agent tool names to existing chain capabilities

- [x] Each functional requirement has an acceptance scenario (FR-001 US1, FR-002 US3.1,
      FR-003 US3.3, FR-004 docs task T004, FR-005 SC-003).
- [x] Each mapped capability exists as a pattern side today (`http_request`, `browse_url`,
      `vector_store_read`).
- [x] No chain pattern is added or changed.
- [x] Variants and non-mapped names are listed under Assumptions with what would overturn them.
- [x] The `tool_` id prefix from the LangChain adapter is covered.
- [x] Known limit recorded: a graph with only the three tools forms no chain.
- [x] Tests use only synthetic in-memory graphs.
- [x] No new dependency.
