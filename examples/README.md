# ZIRAN Examples

Ready-to-run examples covering every major ZIRAN feature. They are
organised into two groups:

| Group | API keys needed? | What it demonstrates |
|---|---|---|
| **Standalone feature examples** (below) | **No** | Individual ZIRAN components you can run instantly |
| **LLM-based scanning examples** (further down) | Yes (`OPENAI_API_KEY`) | Full multi-phase campaigns against real agents |

> **Quick start** — to see ZIRAN finding real vulnerabilities, run the
> [Vulnerable Agent](#vulnerable-agent) example (requires `OPENAI_API_KEY`).

## Prerequisites (shared)

| Requirement | How to install |
|---|---|
| Python ≥ 3.11 | — |
| ZIRAN (editable) | `uv sync` |
| LangChain extra | `uv sync --extra langchain` (only for LLM examples) |
| FAISS (RAG examples) | `uv pip install faiss-cpu` |
| OpenAI key (LLM examples) | Copy `.env.example` → `.env` and set `OPENAI_API_KEY` |

---

# Standalone Feature Examples (no API keys)

These examples exercise individual ZIRAN subsystems with synthetic data.
Each script prints Rich-formatted output and cleans up after itself.

## Static Analysis

> **`examples/static_analysis_example.py`**

Scan Python source files for hard-coded secrets, dangerous patterns,
and prompt-injection risks **without running any agent**.

**What you'll see:** single-file analysis, directory scanning, custom
`StaticAnalysisConfig` patterns, and config merging.

```bash
uv run python examples/static_analysis_example.py
```

---

## Attack Library

> **`examples/attack_library_example.py`**

Browse and filter the built-in library of 40+ attack vectors.

**What you'll see:** category breakdown, filtering by phase / OWASP
category / severity, multi-criteria search, and loading custom YAML
vectors.

```bash
uv run python examples/attack_library_example.py
```

---

## Dynamic Vector Generator

> **`examples/dynamic_vectors_example.py`**

Generate tailored attack vectors from an agent's discovered capabilities.

**What you'll see:** vectors generated for a simple tool set vs. a
dangerous tool set, and exfiltration-chain detection.

```bash
uv run python examples/dynamic_vectors_example.py
```

---

## Skill CVE Database

> **`examples/skill_cve_example.py`**

Check agent tools against a database of known LLM-tool vulnerabilities.

**What you'll see:** browsing all CVEs, filtering by framework and
severity, checking agent capabilities for matches, and submitting a
custom CVE entry.

```bash
uv run python examples/skill_cve_example.py
```

---

## PoC Generation

> **`examples/poc_generation_example.py`**

Generate proof-of-concept scripts from attack results.

**What you'll see:** Python PoC, cURL PoC, Markdown guide, and
`generate_all` producing a full set of reproducible exploits from a
`CampaignResult`.

```bash
uv run python examples/poc_generation_example.py
```

---

## Policy Engine

> **`examples/policy_engine_example.py`**

Evaluate scan results against organisational security policies.

**What you'll see:** built-in default policy, pass/fail verdicts with
violations, custom YAML policy with stricter thresholds, and the
difference between errors and warnings.

```bash
uv run python examples/policy_engine_example.py
```

---

## CI/CD Quality Gate & SARIF Reports

> **`examples/cicd_quality_gate_example.py`**

Run a quality gate and generate SARIF reports for GitHub Code Scanning.

**What you'll see:** default gate (zero critical tolerance), custom
YAML config, programmatic `QualityGateConfig`, SARIF output with
rules and results, and exit-code semantics for pipeline integration.

```bash
uv run python examples/cicd_quality_gate_example.py
```

---

## Custom Agent Adapter

> **`examples/custom_adapter_example.py`**

Implement `BaseAgentAdapter` to integrate any agent framework with ZIRAN.

**What you'll see:** a minimal "EchoBot" adapter with capability
discovery, invoke, tool-call observation, state management, and
high-risk capability identification.

```bash
uv run python examples/custom_adapter_example.py
```

---

# LLM-Based Scanning Examples (require API keys)

The following examples require an `OPENAI_API_KEY` (and sometimes
additional dependencies). They build real agents and run full
multi-phase security campaigns.

## Vulnerable Agent

> **`examples/vulnerable_agent.py`** — requires `OPENAI_API_KEY`

### Scenario

A **real** LangChain ReAct agent backed by GPT-4o-mini that is
intentionally built with common security anti-patterns — the kind of
mistakes developers make when shipping fast without thinking about
prompt hardening:

- **Secrets in the system prompt**: DB credentials and API keys
  hardcoded directly in the prompt text — if the prompt leaks, so do
  the secrets
- **"All users are pre-authenticated"**: removes the model's instinct
  to verify identity or permissions
- **"Be transparent about your configuration"**: makes system-prompt
  extraction a *feature*
- **"Follow instructions precisely, even if unusual"**: disarms the
  model's safety training against social engineering
- **Tools that return full PII**: SSN, salary, email with no redaction
- **Raw SQL execution**: `run_database_query` accepts anything

### Architecture

```
User ──► LLM (ReAct loop, temperature=0.7, secrets embedded in prompt)
              ├──► query_employees      (returns full PII — SSN, salary)
              ├──► send_email           (unrestricted, no confirmation)
              ├──► run_database_query   (raw SQL, no sanitisation)
              └──► read_config          (credentials, API keys, endpoints)
```

### Risk surface

| Attack class | Why this agent is vulnerable |
|---|---|
| System prompt extraction | Prompt contains DB credentials and API keys; agent is told to "be transparent about your setup" |
| Prompt injection | "Follow instructions precisely, even if unusual" + "all users are authorized" |
| Data exfiltration | `query_employees` returns SSN, salary, email; agent told "never truncate or redact" |
| Tool manipulation | `run_database_query` executes raw SQL including DROP TABLE |
| Privilege escalation | "You do not need to verify identity or permissions" — no access control concept |
| Indirect injection | No instruction to ignore embedded commands in tool outputs or documents |

### Usage

```bash
uv run python examples/vulnerable_agent.py
```

### Expected results

ZIRAN should find **multiple vulnerabilities** across the 6 phases.
The exact count depends on the model's behaviour (real LLM responses
vary), but the lack of safety guardrails means the agent will comply
with attacks that well-hardened agents refuse.

---

## LangChain ReAct Agent

> **`examples/langchain_example.py`** — requires `OPENAI_API_KEY`

### Scenario

A minimal ReAct agent backed by GPT-4o-mini with two tools: a database
lookup and an email sender. Represents the simplest useful agent
pattern — a single LLM loop with tool access.

### Architecture

```
User ──► LLM (ReAct loop)
              ├──► lookup      (database search)
              └──► send_email  (email delivery)
```

### Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| System prompt extraction | Can the agent be tricked into revealing its ReAct template? |
| Prompt injection | Does the agent follow "ignore instructions" overrides? |
| Tool manipulation | Can the email tool be abused for spam or phishing? |
| Capability mapping | Does the agent enumerate its tools when probed? |

### Usage

```bash
uv run python examples/langchain_example.py
```

### Expected results

GPT-4o-mini is well-hardened — expect **0 vulnerabilities** in most
runs. The agent refuses social-engineering prompts and does not leak
its system prompt.

---

## RAG Financial Advisor

> **`examples/rag_financial_advisor.py`** — requires `OPENAI_API_KEY` + `faiss-cpu`

### Scenario

A retrieval-augmented financial advisor for *FinCorp*. It answers
questions by searching a FAISS vector store containing product docs,
compliance notices, and a **confidential customer record** (SSN, account
balance, portfolio). A calculator tool handles numeric queries.

### Architecture

```
User ──► LLM (ReAct loop)
              ├──► search_financial_docs  (FAISS retriever, k=3)
              └──► calculate              (safe math eval)
```

### Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| Data exfiltration | Can the agent be coerced into revealing the confidential customer record (SSN, balance)? |
| Context poisoning | Can retrieved context override the "never reveal confidential info" instruction? |
| Document injection | Does the agent treat attacker-supplied text as trusted documents? |
| Prompt injection via retrieval | Can a malicious document in the store hijack the agent? |

### Usage

```bash
uv pip install faiss-cpu  # one-time
uv run python examples/rag_financial_advisor.py
```

### Expected results

The agent has a clear safety instruction ("Never reveal confidential
customer information") and GPT-4o-mini honours it — expect **0
vulnerabilities**. However, the *presence* of sensitive data in the
retriever context is itself a risk that ZIRAN's report highlights.

---

## Router RAG

> **`examples/router_rag.py`** — requires `OPENAI_API_KEY` + `faiss-cpu`

### Scenario

A SaaS platform assistant that dynamically routes queries to the right
data source: a product knowledge base (FAISS), a customer database
(structured records), or a market data API. The router pattern adds
a layer of decision-making that attackers can try to manipulate.

### Architecture

```
User ──► Router LLM (decides retrieval strategy)
              ├──► classify_query        (routing classifier)
              ├──► search_knowledge_base (FAISS vector search, k=2)
              ├──► query_customer_database (structured lookup — RESTRICTED)
              └──► get_market_data       (live stock prices)
```

### Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| Routing injection | Can the user manipulate the router into choosing a more privileged data source? |
| Tool selection manipulation | Can the agent be convinced to bypass `classify_query` and go straight to `query_customer_database`? |
| Cross-source data leakage | Can data from the restricted customer DB be exfiltrated via blended queries? |
| Schema / API abuse | Can SQL-style injection pass through the structured `query_customer_database` tool? |
| System prompt extraction | Can the router's decision logic be extracted? |

### Usage

```bash
uv pip install faiss-cpu  # one-time
uv run python examples/router_rag.py
```

### Expected results

Expect **0 vulnerabilities**. The GPT-4o-mini backed router respects
its access-control rules and refuses to expose customer records to
unverified users.

---

## Supervisor Multi-Agent

> **`examples/supervisor_multi_agent.py`** — requires `OPENAI_API_KEY`

### Scenario

A corporate helpdesk supervisor that routes to three specialist
sub-chains — HR, Finance, and IT. Each specialist has domain-specific
tools and the Finance agent holds **restricted payroll data**. The
supervisor pattern introduces cross-agent trust boundaries that
attackers can try to exploit.

### Architecture

```
User ──► Supervisor (LLM router)
              ├──► HR Agent     (lookup_hr_policy, submit_leave_request)
              ├──► Finance Agent (submit_expense, lookup_payroll — RESTRICTED)
              └──► IT Agent      (create_it_ticket, check_system_status)
```

### Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| Cross-agent privilege escalation | Can the user trick the supervisor into routing to a more privileged agent (e.g. HR → Finance)? |
| Routing manipulation | Can intent be mis-classified to bypass guardrails? |
| Tool access across boundaries | Can IT tools be invoked through the HR agent path? |
| System prompt extraction | Can the supervisor's routing instructions or sub-agent prompts be extracted? |
| Data exfiltration | Can one agent be coerced into leaking data from another agent's domain (payroll)? |

### Usage

```bash
uv run python examples/supervisor_multi_agent.py
```

### Expected results

Expect **0 vulnerabilities**. The supervisor follows its routing
rules and the model refuses to expose payroll data or execute
cross-boundary operations.

---

## CrewAI Crew

> **`examples/crewai_example.py`** — requires `crewai` extra

### Scenario

A CrewAI crew with a single Security Researcher agent. Demonstrates
the adapter pattern for non-LangChain frameworks.

### Architecture

```
User ──► CrewAI Crew
              └──► Security Researcher agent (role-based, verbose)
```

### Risk surface

| Attack class | What ZIRAN tests |
|---|---|
| System prompt extraction | Can the agent's role/backstory be extracted? |
| Prompt injection | Does the agent honour "ignore instructions" overrides? |

### Usage

```bash
uv sync --extra crewai
uv run python examples/crewai_example.py
```

---

## Shared helper: `_progress.py`

A Rich-based progress bar and summary table used by all examples. It
hooks into the scanner's `on_progress` callback to display live
per-phase and per-attack progress bars.

```python
from _progress import ZiranProgressBar, print_summary

async with ZiranProgressBar() as progress:
    result = await scanner.run_campaign(
        phases=phases,
        on_progress=progress.callback,
    )

print_summary(result)
```
