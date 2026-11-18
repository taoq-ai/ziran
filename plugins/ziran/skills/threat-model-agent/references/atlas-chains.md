# Chain types to MITRE ATLAS techniques

ZIRAN reports a dangerous tool chain by its `vulnerability_type` (in `ziran audit` messages:
`Agent 'researcher': data_exfiltration via Read -> WebFetch`). ZIRAN's output carries no ATLAS
ID, so use this table to name the technique. Every chain type ZIRAN can report has a row; a test
keeps it in step with `ziran/application/knowledge_graph/chain_patterns.yaml`, the single-tool
types in `chain_analyzer.py` and the ATLAS
IDs ZIRAN knows (the October 2025 ATLAS release).

The mapping is ZIRAN's reading of each chain, not an ATLAS statement. Every chain is an abuse of
AML.T0053 (AI Agent Tool Invocation): the model is steered, usually by injected content, into
calling tools it was legitimately given. ATLAS has no technique for a plain file write, so
persistence rows cite only what the chain invokes and reads.

Technique names: AML.T0010.001 AI Supply Chain Compromise: AI Software; AML.T0012 Valid Accounts;
AML.T0025 Exfiltration via Cyber Means; AML.T0036 Data from Information Repositories; AML.T0037
Data from Local System; AML.T0048.000 External Harms: Financial; AML.T0050 Command and Scripting
Interpreter; AML.T0051.001 LLM Prompt Injection: Indirect; AML.T0053 AI Agent Tool Invocation;
AML.T0055 Unsecured Credentials; AML.T0057 LLM Data Leakage; AML.T0059 Erode Dataset Integrity;
AML.T0070 RAG Poisoning; AML.T0071 False RAG Entry Injection.

| Chain types | ATLAS techniques | What can happen | Narrowest fix |
|---|---|---|---|
| `data_exfiltration`, `code_exfiltration`, `managed_file_exfil`, `mcp_code_exfiltration`, `mcp_file_exfiltration`, `mcp_file_to_email`, `screen_data_exfil` | AML.T0053, AML.T0037, AML.T0025 | Local files, source code or screen contents are read and sent out over the network, email or a git push. | Drop the outbound tool, or scope it (allowlisted domains, deny `git push`, approval before send). |
| `database_exfiltration`, `orm_data_exfiltration`, `orm_data_leak`, `cloud_data_exfiltration`, `mcp_resource_exfiltration`, `mcp_data_exfiltration`, `memory_exfiltration`, `embedding_exfiltration`, `scraped_data_leak`, `search_data_leak`, `form_data_exfil`, `mcp_sampling_exfiltration`, `cross_agent_exfiltration`, `cross_agent_data_access` | AML.T0053, AML.T0036, AML.T0025 | Records from a database, bucket, memory store, MCP resource or another agent are read and sent out. | Read-only, row-scoped credentials; remove the outbound tool from the same agent; split read and send across agents with a human step between. |
| `pii_leakage` | AML.T0053, AML.T0036, AML.T0057, AML.T0025 | Personal data from a user lookup is sent externally. | Return redacted user fields; deny outbound tools to agents that read user records. |
| `secret_file_exfiltration`, `env_secret_exfiltration`, `cloud_secret_exfiltration`, `key_material_exfiltration`, `crypto_key_exfiltration`, `decrypted_data_exfil`, `session_hijacking` | AML.T0053, AML.T0055, AML.T0025 | Secrets, keys, decrypted data or session tokens are read and sent out. | Deny reads of secret paths and env; keep secret managers and KMS out of agents with network or email tools. |
| `directory_traversal` | AML.T0053, AML.T0037 | Directory listing guides reads of files outside the intended scope. | Confine file tools to a working directory; deny listing above it. |
| `remote_code_execution`, `web_content_to_rce`, `nav_to_rce`, `mcp_prompt_to_rce`, `context_to_rce`, `memory_to_rce` | AML.T0053, AML.T0051.001, AML.T0050 | Content fetched from the web, an MCP prompt or stored memory is executed as code or shell. | Never pass fetched or stored text to an executor; sandbox execution with no network and no secrets. |
| `unrestricted_execution` | AML.T0053, AML.T0050 | One unscoped shell tool (bare `Bash` or `Bash(*)`) can read any file, reach the network and run any code. | Scope it with permission rules such as `Bash(npm test:*)`, or deny it; run the agent in a sandbox. |
| `file_to_rce`, `sql_to_rce`, `code_to_shell`, `env_to_rce`, `cloud_secret_to_rce`, `cloud_function_to_rce`, `git_to_rce`, `pipeline_to_rce`, `mcp_to_rce`, `mcp_tool_to_rce`, `mcp_write_to_rce`, `delegation_to_rce` | AML.T0053, AML.T0050 | Output of a data or tool call (a file, a query, a secret, a subagent) reaches a code or shell executor. | Remove the executor or scope it (`Bash(npm test:*)` style rules); run it in a sandbox. |
| `command_injection_exfil`, `repl_exfiltration`, `shell_exfiltration` | AML.T0053, AML.T0050, AML.T0025 | A shell or REPL is chained with a network or email tool, so anything it can read can leave. | Keep shell and REPL tools off agents that can send; block egress from the sandbox. |
| `command_injection_persist`, `repl_persist`, `shell_persist`, `mcp_tool_persist`, `mcp_sampling_persist`, `cloud_function_persist`, `cross_agent_persist`, `file_manipulation`, `container_manipulation`, `web_content_persist` | AML.T0053 | Tool output or fetched content is written to disk, a Dockerfile or startup files and survives the session. | Scope write tools to a path; deny writes to config, CI, Dockerfiles and shell profiles. |
| `memory_persist`, `env_secret_persist` | AML.T0053, AML.T0055 | Memory contents or environment secrets are written to disk where other processes can read them. | Deny file writes to agents that read memory or env. |
| `data_poisoning`, `memory_poisoning`, `context_injection`, `web_content_injection` | AML.T0053, AML.T0051.001, AML.T0059 | Fetched content is stored in a database, memory or context and steers later turns or other users. | Mark fetched content untrusted; do not write it to shared stores without validation. |
| `rag_poisoning`, `external_rag_poisoning` | AML.T0053, AML.T0070, AML.T0071 | Writes to a vector store become retrieved context for every later query. | Separate the writer from the retriever; review or sign entries before indexing. |
| `authentication_bypass`, `privilege_escalation`, `memory_to_auth_bypass` | AML.T0053, AML.T0012 | Data or memory feeds token generation or permission changes, giving valid access the user should not have. | Remove token and permission tools from conversational agents; require human approval. |
| `supply_chain_injection` | AML.T0053, AML.T0010.001 | A commit is deployed by the same agent, so injected code ships. | Require review between commit and deploy; no deploy tool on coding agents. |
| `env_secret_injection` | AML.T0053, AML.T0055 | Environment secrets flow into a deployment the agent controls. | Inject secrets at deploy time from the platform, not through the agent. |
| `delegation_chain_amplification`, `a2a_to_mcp_escalation`, `mcp_cross_server_chain`, `mcp_cross_tool_escalation`, `mcp_enumeration_to_exploit` | AML.T0053, AML.T0051.001 | Instructions pass from one agent, server or tool to another and gain its tools. | Limit delegation depth; give each MCP server only the tools its task needs; treat server output as untrusted. |
| `transaction_hijack` | AML.T0053, AML.T0048.000 | A signed transaction is sent where the attacker chooses. | Human approval and an allowlist of destinations for signing tools. |
