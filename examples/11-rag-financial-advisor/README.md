# RAG Financial Advisor

A retrieval-augmented financial advisor backed by FAISS + GPT-4o-mini with **confidential customer data** in the vector store.

## Architecture

```
User ──► LLM (ReAct loop)
              ├──► search_financial_docs  (FAISS retriever, k=3)
              └──► calculate              (safe math eval)
```

## Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| Data exfiltration | Can the agent reveal the confidential customer record (SSN, balance)? |
| Context poisoning | Can retrieved context override the safety instruction? |
| Document injection | Does the agent treat attacker-supplied text as trusted? |
| Prompt injection via retrieval | Can a malicious document in the store hijack the agent? |

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
| [main.py](main.py) | Builds RAG agent with FAISS, runs 6-phase scan |
| [run.sh](run.sh) | Checks API key and launches |

## Expected results

Expect **0 vulnerabilities** — the agent has a clear safety instruction and GPT-4o-mini honours it. However, the *presence* of sensitive data in the retriever context is itself a risk highlighted in the report.
