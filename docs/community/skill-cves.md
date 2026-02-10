# Skill CVE Database

KOAN maintains a curated database of known security vulnerabilities in popular AI agent tools and skills.

## What is a Skill CVE?

A **Skill CVE** (Common Vulnerabilities and Exposures) is a documented security vulnerability in a specific agent tool or skill. Unlike traditional CVEs that track software bugs, Skill CVEs track **inherent security risks** in how agent tools can be misused.

## Naming Convention

```
CVE-AGENT-YYYY-NNN
```

Example: `CVE-AGENT-2026-001` — ShellTool RCE in LangChain

## Current Database

KOAN ships with 15 seed CVEs covering:

- **LangChain** — ShellTool, PythonREPL, SQL tools, file tools, Gmail, search
- **CrewAI** — ScrapeWebsite, FileRead, CodeInterpreter
- **MCP** — Tool invocation without scope validation

## Checking Your Agent

```python
from koan.application.skill_cve import SkillCVEDatabase

db = SkillCVEDatabase()
matches = db.check_agent(discovered_capabilities)

for cve in matches:
    print(f"{cve.cve_id}: {cve.skill_name}")
    print(f"  Severity: {cve.severity}")
    print(f"  Risk: {cve.description}")
    print(f"  Fix: {cve.remediation}")
```

## Submitting a Skill CVE

Found a vulnerability in an agent tool? Help the community by submitting it:

1. **Open a GitHub issue** using the [Skill CVE template](https://github.com/taoq-ai/koan/issues/new?template=skill_cve.md)
2. Include:
   - Tool/skill name and version
   - Framework (LangChain, CrewAI, etc.)
   - Vulnerability type and severity
   - Description and proof of concept
   - Remediation guidance
3. The KOAN team will review, assign a CVE ID, and add it to the database

## Vision

We envision a community-maintained database of agent tool vulnerabilities — similar to how the traditional CVE system works, but focused on the unique risks of AI agent tools.

As the ecosystem grows, this database will become an essential resource for:
- **Developers** — Know the risks of the tools you're giving your agents
- **Security teams** — Audit agent deployments against known vulnerabilities
- **Researchers** — Track and document new vulnerability patterns
