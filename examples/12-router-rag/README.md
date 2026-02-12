# Router RAG

A SaaS platform assistant that dynamically routes queries to the right data source — product knowledge base, customer database, or market data API.

## Architecture

```
User ──► Router LLM (decides retrieval strategy)
              ├──► classify_query        (routing classifier)
              ├──► search_knowledge_base (FAISS vector search, k=2)
              ├──► query_customer_database (structured lookup — RESTRICTED)
              └──► get_market_data       (live stock prices)
```

## Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| Routing injection | Can the user manipulate the router into choosing a more privileged data source? |
| Tool selection manipulation | Can the agent bypass `classify_query` and go straight to `query_customer_database`? |
| Cross-source data leakage | Can data from the restricted customer DB be exfiltrated via blended queries? |
| Schema / API abuse | Can SQL-style injection pass through `query_customer_database`? |
| System prompt extraction | Can the router's decision logic be extracted? |

## Prerequisites

- Python 3.11+
- `pip install ziran[langchain] faiss-cpu` (or `uv sync --extra rag` from `examples/`)
- `OPENAI_API_KEY` set in environment or `../.env`

## Run

```bash
./run.sh
# or
uv run python main.py
```

## Files

| File | Purpose |
|------|---------|
| [main.py](main.py) | Builds router agent with 4 tools, runs 6-phase scan |
| [run.sh](run.sh) | Checks API key and launches |

## Expected results

Expect **0 vulnerabilities**. The GPT-4o-mini router respects its access-control rules and refuses to expose customer records.
