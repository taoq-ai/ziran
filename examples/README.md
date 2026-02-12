# ZIRAN Examples

Hands-on examples that show how to test different AI agent architectures with ZIRAN.

## Quick start

```bash
cd examples/

# install the examples workspace (uses uv)
uv sync                        # base examples (no API key needed)
uv sync --extra langchain      # + LangChain examples
uv sync --extra crewai         # + CrewAI example
uv sync --extra rag            # + RAG / FAISS examples
uv sync --extra all            # everything

# run any example
cd 01-static-analysis
./run.sh
```

> **Tip:** Copy `.env.example` to `.env` and fill in your API keys before running
> examples 09–14.

---

## No API key required

These examples use ZIRAN's built-in scanner without calling any LLM.

| # | Example | What it demonstrates |
|---|---------|---------------------|
| 01 | [Static Analysis](01-static-analysis/) | Analyse raw Python source code for security issues |
| 02 | [Attack Library](02-attack-library/) | Load the built-in attack library and generate custom vectors from YAML |
| 03 | [Dynamic Vectors](03-dynamic-vectors/) | Create dynamic attack vectors with inline YAML |
| 04 | [Skill CVE](04-skill-cve/) | Query the embedded CVE knowledge base |
| 05 | [PoC Generation](05-poc-generation/) | Generate a proof-of-concept exploit from a CVE entry |
| 06 | [Policy Engine](06-policy-engine/) | Define a YAML security policy and evaluate findings against it |
| 07 | [CI/CD Quality Gate](07-cicd-quality-gate/) | Fail a build when findings exceed a YAML-configured threshold |
| 08 | [Custom Adapter](08-custom-adapter/) | Implement `AgentAdapter` for any agent framework |

## LLM scans (API key required)

These examples call an LLM provider. Set `OPENAI_API_KEY` in `../.env` first.

| # | Example | Agent architecture | Extra deps |
|---|---------|-------------------|------------|
| 09 | [LangChain Scan](09-langchain-scan/) | ReAct agent with calculator + search tools | `--extra langchain` |
| 10 | [Vulnerable Agent](10-vulnerable-agent/) | Intentionally weak HR chatbot (finds vulns!) | `--extra langchain` |
| 11 | [RAG Financial Advisor](11-rag-financial-advisor/) | FAISS-backed advisor with confidential client data | `--extra rag` |
| 12 | [Router RAG](12-router-rag/) | Dynamic router → knowledge base / customer DB / market API | `--extra rag` |
| 13 | [Supervisor Multi-Agent](13-supervisor-multi-agent/) | Supervisor delegates to HR, Finance, IT sub-agents | `--extra langchain` |
| 14 | [CrewAI Scan](14-crewai-scan/) | CrewAI research crew (native adapter, no LangChain) | `--extra crewai` |

---

## Folder structure

Every example lives in its own folder with:

```
NN-example-name/
├── main.py          # the example script
├── run.sh           # one-click runner (checks env, launches uv run)
├── README.md        # what it does, architecture, expected results
└── *.yaml / *.py    # config or sample files (where needed)
```

Reports are written to `NN-example-name/reports/` (git-ignored).
