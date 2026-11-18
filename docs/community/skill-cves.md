# Skill CVE Database

ZIRAN maintains a curated database of known security vulnerabilities in popular AI agent tools and skills.

## What is a Skill CVE?

The database contains two types of entries:

- **Real CVEs** — Verified vulnerabilities from the NVD/GitHub Advisory Database (e.g. `CVE-2025-68664`)
- **Design Risks** — Architectural weaknesses documented in OWASP LLM Top 10 and framework security guides (e.g. `DESIGN-RISK-001`)

## ID Format

```
CVE-YYYY-NNNNN      # Real CVE from NVD
DESIGN-RISK-NNN     # OWASP/framework design risk
```

## Current Database

ZIRAN ships with 49 seed entries (36 CVEs, 13 design risks) covering:

### Real CVEs
- **LangChain** — CVE-2023-46229 (SSRF), CVE-2025-68664 (serialization injection), CVE-2025-65106 (template injection), CVE-2025-46059 (prompt injection), CVE-2025-8709 (SQL injection), CVE-2025-64439 (RCE), CVE-2025-2828 (SSRF)
- **MCP** — CVE-2025-53109 (symlink bypass), CVE-2025-53110 (path traversal), CVE-2025-68145 (git path bypass), CVE-2025-6514 (command injection), CVE-2026-27825 (file write RCE)
- **mcp-atlassian file read and exfiltration** — CVE-2026-77260, CVE-2026-77248, CVE-2026-77262, CVE-2026-77253, CVE-2026-77246, CVE-2026-73498, CVE-2026-77255
- **MCP SDKs and servers** — CVE-2026-116686 (Python SDK `$ref` fetch), CVE-2026-104850 (TypeScript SDK OAuth credentials), CVE-2026-32871 (FastMCP OpenAPI SSRF), CVE-2026-105697 (Langflow MCP stdio command injection)
- **Coding agents** — CVE-2025-61260 (Codex CLI MCP config), CVE-2026-54316, CVE-2026-39861, CVE-2026-88968, CVE-2026-55607, CVE-2026-40068 (Claude Code)
- **Agent frameworks** — CVE-2026-113663 (AG2 SandboxShellTool), CVE-2026-7700 (Langflow Smart Transform), CVE-2026-59207, CVE-2026-65015, CVE-2026-86996 (n8n AI Agents)
- **Other** — CVE-2025-32711 (M365 Copilot), CVE-2026-29783 (Copilot CLI)

### Design Risks (OWASP LLM Top 10)
- **LangChain** — ShellTool, RequestsGetTool, ReadFileTool, WriteFileTool, QuerySQLDataBaseTool, PythonREPLTool, SerpAPIWrapper, ConversationBufferMemory, GmailSendMessage, TavilySearchResults
- **CrewAI** — ScrapeWebsiteTool, FileReadTool, CodeInterpreterTool

## Checking Your Agent

```python
from ziran.application.skill_cve import SkillCVEDatabase

db = SkillCVEDatabase()
matches = db.check_agent(discovered_capabilities)

for cve in matches:
    print(f"{cve.cve_id}: {cve.skill_name}")
    print(f"  Severity: {cve.severity}")
    print(f"  Type: {cve.risk_type}")
    print(f"  Risk: {cve.description}")
    print(f"  Fix: {cve.remediation}")
```

## Submitting a Skill CVE

Found a vulnerability in an agent tool? Help the community by submitting it:

1. **Open a GitHub issue** using the [Skill CVE template](https://github.com/taoq-ai/ziran/issues/new?template=skill_cve.md)
2. Include:
   - Tool/skill name and version
   - Framework (LangChain, CrewAI, etc.)
   - Vulnerability type and severity
   - Description and proof of concept
   - Remediation guidance
   - **Real CVE ID** if available (from NVD or GitHub advisories)
3. The ZIRAN team will review and add it to the database

## Vision

We envision a community-maintained database of agent tool vulnerabilities — similar to how the traditional CVE system works, but focused on the unique risks of AI agent tools.

As the ecosystem grows, this database will become an essential resource for:
- **Developers** — Know the risks of the tools you're giving your agents
- **Security teams** — Audit agent deployments against known vulnerabilities
- **Researchers** — Track and document new vulnerability patterns
