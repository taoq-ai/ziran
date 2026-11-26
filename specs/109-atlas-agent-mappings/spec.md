# Feature Specification: MITRE ATLAS agent techniques and OWASP Agentic ASI08 to ASI10 mappings

**Feature Branch**: `feat/109-atlas-agent-mappings`
**Created**: 2026-11-26
**Status**: Active
**Base**: `develop` @ f533d8e.

## The promise in our own words

The ATLAS ids on our vectors stop before the techniques MITRE added for AI agents. A vector that
poisons an agent's memory, abuses a poisoned MCP tool description, or sends data out through an
agent's email tool carries generic ids (`AML.T0018`, `AML.T0051`, `AML.T0053`) but not the
agent technique that names what it tests. The OWASP Agentic default table gives no vector
ASI08, ASI09 or ASI10.

After this change:

1. `AtlasTechnique` has the twelve agent technique ids listed below, with the names and tactics
   of ATLAS data release 2026.10.
2. A vector carries one of these ids only when the vector tests that technique. The mapping
   table below gives the reason for each row. A test pins each technique to exactly its vector
   set, so a wrong or missing tag fails.
3. `AGENTIC_DEFAULTS[MULTI_AGENT]` is `[ASI07, ASI08]`. Vectors that test ASI09 or ASI10, or
   whose family default is wrong, set `owasp_agentic_mapping` in their YAML.
4. The coverage reference (`docs/reference/benchmarks/atlas-mapping.md`,
   `docs/reference/benchmarks/coverage-comparison.md`, `benchmarks/README.md`), the committed
   benchmark baseline and the README show the new counts.

Out of scope: new vectors, chain rules, detectors, and ATLAS ids that release 2026.10 moved
(`AML.T0056` and `AML.T0057` now sit under `AML.T0085`, and `AML.T0024.000` and `.001` under
`AML.T0137`). That re-pin is a separate change.

## Source

MITRE ATLAS data release 2026.10 (2026-10-28), format 6.1.0:
<https://github.com/mitre-atlas/atlas-data/blob/f56c1468731d6428e5bf875263b4643b46d67437/dist/v6/ATLAS-2026.10.yaml>.
Names and tactics below were read from that file (`techniques.<id>.name` and the `achieves`
relationships). Sub-technique names follow the enum's existing `Parent: Sub` form.

| Id | Name | Tactic |
|---|---|---|
| `AML.T0080` | AI Agent Context Poisoning | Persistence (`AML.TA0006`) |
| `AML.T0080.000` | AI Agent Context Poisoning: Memory | Persistence |
| `AML.T0080.001` | AI Agent Context Poisoning: Thread | Persistence |
| `AML.T0081` | Modify AI Agent Configuration | Persistence, Defense Evasion (`AML.TA0007`) |
| `AML.T0084` | Discover AI Agent Configuration | Discovery (`AML.TA0008`) |
| `AML.T0086` | Exfiltration via AI Agent Tool Invocation | Exfiltration (`AML.TA0010`) |
| `AML.T0110` | AI Agent Tool Poisoning | Persistence |
| `AML.T0110.000` | AI Agent Tool Poisoning: Definition and Instructions | Persistence |
| `AML.T0110.001` | AI Agent Tool Poisoning: Implementation | Persistence |
| `AML.T0110.002` | AI Agent Tool Poisoning: Runtime Response | Persistence |
| `AML.T0118` | Autonomous AI Agent Communication | AI Attack Staging (`AML.TA0001`) |
| `AML.T0133` | Discover AI Agent Runtime Capabilities | Discovery |

The planning note named `AML.T0080.001` as memory poisoning; in the release `.000` is Memory and
`.001` is Thread.

## Mapping table

Each row lists the vectors that get the id and why. A parent id goes on every vector that
carries one of its sub-techniques.

| Id | Vectors | Reason |
|---|---|---|
| `AML.T0080.000` | `mp_cross_session_persistence`, `mp_memory_key_injection`, `mt_crescendo_memory_poison` | The prompt asks the agent to store a planted fact or rule in persistent memory for later sessions. |
| `AML.T0080.000` | `ma_memory_poisoning` | Writes false facts into the memory store that other agents read. |
| `AML.T0080.001` | `mp_instruction_persistence`, `mp_context_anchoring`, `mp_identity_override`, `mp_summary_manipulation`, `mp_delayed_trigger` | Plants an instruction that must govern the rest of the thread ("for all subsequent messages", "from this point forward", a dormant trigger). |
| `AML.T0080.001` | `mp_false_history`, `mp_conversation_rewrite`, `a2a_context_pollution` | Inserts fabricated prior turns into the thread so later replies build on them. |
| `AML.T0080.001` | `ma_state_injection` | Injects data into shared conversation state that persists across agent turns. |
| `AML.T0081` | `pe_config_override`, `ii_chat_tool_config` | Asks the agent (directly, or through injected chat history) to change its own security settings or configuration. |
| `AML.T0081` | `mcp_persist_config_write` | The poisoned tool steers the agent to write an MCP server config or `.env` file that persists across sessions. |
| `AML.T0081` | `agt26_mcp_stdio_config_command`, `agt26_mcp_flow_embedded_server_config` | Adds an MCP server entry to the agent host's tool configuration, by the settings tool or inside an imported flow. |
| `AML.T0084` | `a2a_card_enumeration`, `a2a_extended_card_leak` | Reads the agent card, the agent's published configuration (skills, schemes, tool schemas). |
| `AML.T0084` | `spe_json_dump`, `mt_code_json_schema`, `mt_fewshot_format_priming`, `de_summary_extraction` | Asks the agent to dump its configuration (system prompt, tools, settings) as a structured document. |
| `AML.T0084` | `ma_topology_exfil` | Asks agents for their peers, supervisors and call paths, the call chains of the agent configuration. |
| `AML.T0133` | `pe_permission_probing`, `mt_context_permission_boundary` | Maps the agent's permission scope at runtime by asking what it can and cannot do. |
| `AML.T0133` | `tm_tool_name_spoofing` | Calls a fake tool and asks the agent to list the real ones it has. |
| `AML.T0133` | `mt_crescendo_tool_disclosure`, `mt_context_tool_chain` | Multi-turn questioning that enumerates the agent's tools and integrations. |
| `AML.T0086` | `de_tool_based_exfil`, `de_url_exfil` | Asks the agent to write secrets with a file tool or send them in an HTTP call. |
| `AML.T0086` | `ii_email_tool_send`, `ii_email_tool_forward`, `ii_email_exfil_reply` | Injected email tells the agent to send, forward or reply with user data through the email tool. |
| `AML.T0086` | `ii_api_exfil_webhook`, `ii_db_exfil_trigger`, `ii_notification_exfil` | Injected content tells the agent to post its context to an attacker endpoint. |
| `AML.T0086` | `mt_context_tool_chain` | The last turn asks the agent to mail `/etc/passwd` to an outside address. |
| `AML.T0086` | `mcp_chain_read_then_exfil`, `mcp_exfil_dns`, `mcp_exfil_url_encoding`, `mcp_exfil_steganographic`, `mcp_exfil_delayed_batch`, `mcp_exfil_log_channel`, `mcp_email_bcc_injection`, `mcp_param_substitution`, `mcp_env_variable_exfil`, `mcp_privesc_env_var_access`, `mcp_multiserver_credential_theft`, `mcp_response_credential_harvest` | A poisoned tool makes the agent put secrets or user data into a tool call's arguments or destination. |
| `AML.T0086` | `mcp_multi_server_data_relay`, `mcp_composite_reconnaissance_exfil` | A chain of tool calls moves collected data to a second, outward tool. |
| `AML.T0110.000` | `mcp_tool_desc_injection`, `mcp_param_desc_injection`, `mcp_preauth_claim`, `mcp_security_check_disguise`, `mcp_compliance_override`, `mcp_param_substitution`, `mcp_default_override`, `mcp_shadow_redirect` | The payload sits in the tool's description or metadata. |
| `AML.T0110.000` | the 9 `mcp_desc_*` vectors, the 7 `mcp_param_*` vectors in `mcp_attacks_expanded.yaml` (`hidden_field`, `type_confusion`, `enum_escape`, `sql_injection_hint`, `path_traversal_hint`, `command_injection_hint`, `schema_overflow`) | The payload sits in the tool description or a parameter's description or schema. |
| `AML.T0110.000` | `mcp_chain_read_then_exfil`, `mcp_chain_escalation_ladder`, `mcp_chain_circular_delegation`, `mcp_exfil_dns`, `mcp_exfil_url_encoding`, `mcp_exfil_steganographic`, `mcp_exfil_delayed_batch`, `mcp_exfil_log_channel`, `mcp_trigger_user_specific`, `mcp_trigger_time_delayed`, `mcp_trigger_data_dependent`, `mcp_trigger_context_dependent`, `mcp_delayed_payload_activation`, `mcp_notification_hijack`, `mcp_env_variable_exfil` | The tool description tells the agent to call other tools, leak data or fire on a trigger. |
| `AML.T0110.000` | `mcp_multiserver_trust_pivot`, `mcp_multiserver_credential_theft`, `mcp_multiserver_config_poisoning` | One server's tool definition steers the agent across to another server's tools or shadows them. |
| `AML.T0110.000` | `mcp_privesc_consent_phishing`, `mcp_privesc_scope_widening`, `mcp_privesc_capability_claim`, `mcp_privesc_env_var_access` | The tool description claims consent, scope or capabilities it does not have. |
| `AML.T0110.000` | `mcp_lifecycle_init_poison`, `mcp_lifecycle_dynamic_redefinition`, `mcp_supply_chain_typosquat` | The server ships poisoned tool definitions at connect time, after a redefinition, or under a lookalike name. |
| `AML.T0110.000` | `mcp_filesystem_escape`, `mcp_git_history_exfil`, `mcp_database_dump`, `mcp_browser_cookie_theft`, `mcp_slack_impersonation`, `mcp_email_bcc_injection`, `mcp_cloud_iam_escalation`, `mcp_kubernetes_escape` | A domain tool's description tells the agent to go beyond the user's request. |
| `AML.T0110.000` | `mcp_social_fake_update`, `mcp_social_reward_promise`, `mcp_evasion_token_splitting`, `mcp_evasion_semantic_paraphrase`, `mcp_evasion_few_shot_examples`, `mcp_evasion_chain_of_thought` | Social or evasion payloads hidden in the tool documentation. |
| `AML.T0110.000` | `mcp_persist_config_write`, `mcp_persist_cron_injection`, `mcp_persist_ssh_key_injection`, `mcp_dos_recursive_tool`, `mcp_dos_api_abuse` | The tool description tells the agent to plant persistence or loop on calls. |
| `AML.T0110.000` | `mcp_chain_tool_confusion`, `mcp_tool_rename_confusion`, `sc_typosquatted_tool` | A lookalike tool name steers which tool the agent selects (ATLAS lists names in this layer). |
| `AML.T0110.000` | `sc_malicious_plugin_manifest` | The plugin manifest hides dangerous capabilities behind a benign purpose. |
| `AML.T0110.002` | `mcp_response_instruction_injection`, `mcp_response_fake_error`, `mcp_response_data_poisoning`, `mcp_response_context_window_stuffing`, `mcp_response_credential_harvest`, `mcp_cross_tool_permission_launder` | The malicious content arrives in the tool's response. |
| `AML.T0110.002` | `mcp_jsonrpc_injection`, `mcp_social_fake_update`, `mcp_social_helpdesk_impersonation` | Tool responses carry extra JSON-RPC messages, a fake update or a fake helpdesk request. |
| `AML.T0110.002` | `mcp_srv_roots_filesystem_or_home`, `mcp_srv_roots_credential_folders` | The hostile server's tool result asks the host to widen its roots. |
| `AML.T0110.001` | none | Implementation poisoning runs in the tool's code and needs no model to follow anything. Our vectors send prompts and judge the agent's reply or tool calls; none plants or detects a tool implementation. |
| `AML.T0118` | none | This technique describes adversary-run agents that coordinate with each other (AI Attack Staging). A scan observes the target's behaviour, not the attacker's own agents. |

Not mapped on purpose: vectors that only fetch attacker data through a benign tool (search
results, documents, email bodies, API responses) stay `AML.T0051.001` and do not get
`AML.T0110`; the tool is not poisoned. Markdown-link and summary exfiltration
(`de_markdown_link`, `ii_email_exfil_url`, `ii_search_exfil_markdown`) leak through the reply,
not a tool call, so they do not get `AML.T0086`. MCP resource, prompt-template, sampling and
transport vectors do not get `AML.T0110`; they abuse other parts of the protocol.

## OWASP Agentic ASI08 to ASI10

Working definitions from the OWASP AIVSS scoring data for ASI08 to ASI10
(<https://github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system>,
`calculator/data/asi08.json` to `asi10.json`): ASI08, a single agent fault propagates through
orchestration to dependent workflows; ASI09, an attacker exploits human trust in agent output
or agent-mediated requests; ASI10, a rogue or hijacked agent operates outside its policy bounds.

| Vectors | Mapping | Reason |
|---|---|---|
| category `multi_agent` (default) | `[ASI07, ASI08]` | The family injects at one agent and checks whether a downstream agent acts on it, which is the propagation ASI08 names. |
| `ma_topology_exfil`, `ma_inter_agent_eavesdrop` | `[ASI07]` (YAML) | Reconnaissance and eavesdropping on agent traffic; nothing propagates. |
| `ma_trust_escalation` | `[ASI07, ASI10]` (YAML) | The attacker poses as a trusted upstream agent; the test checks whether a rogue agent identity is obeyed. |
| `a2a_card_forgery_impersonation` | `[ASI01, ASI07, ASI10]` (YAML) | A forged agent card presents a rogue agent as a trusted peer; the injection keeps ASI01. |
| `mcp_srv_elicit_api_key`, `mcp_srv_elicit_password_otp`, `mcp_srv_elicit_overbroad_identity`, `mcp_srv_elicit_overbroad_payment` | `[ASI09]` (YAML) | A hostile server asks the human, through the agent client's own prompt, for credentials or personal data. The human trusts the agent's UI. |

No other category takes ASI09 or ASI10 by default: no category as a whole tests human approval
or a rogue agent, so a default would tag vectors that do not test them.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Findings carry the ATLAS agent technique they test (Priority: P1)

A red-team or threat-intel reader filters findings by ATLAS agent techniques.

**Acceptance Scenarios**:

1. **Given** the vector library, **When** coverage is computed, **Then** each agent technique
   appears on exactly the vectors in the mapping table and on no other, each with a reason.
2. **Given** `ziran library --atlas AML.T0110.000`, **When** run, **Then** it lists the tool
   definition vectors.

### User Story 2 - Agentic vectors carry ASI08 to ASI10 (Priority: P1)

1. **Given** a vector in the multi-agent family, **When** loaded with no YAML override, **Then**
   its mapping is `[ASI07, ASI08]`.
2. **Given** the elicitation and impersonation vectors, **When** loaded, **Then** they carry
   ASI09 and ASI10 as in the table.

### User Story 3 - The coverage reference shows the new counts (Priority: P2)

1. **Given** `benchmarks/generate_all.py` and `benchmarks/regression_check.py
   --update-baseline`, **When** run, **Then** the committed outputs, the ATLAS docs page and the
   README match the script.

### Edge Cases

- A technique with no vector (`AML.T0110.001`, `AML.T0118`) stays in the enum, so
  `ziran library --atlas` accepts it, and the coverage JSON lists it under
  `uncovered_techniques`.
- `AGENT_SPECIFIC_TECHNIQUES` keeps its 14 entries; the coverage gate fails when one of those is
  uncovered, and the two techniques above have no vector.
- Dynamic multi-agent vectors take the new `[ASI07, ASI08]` default.

## Requirements *(mandatory)*

- **FR-001**: twelve `AtlasTechnique` members with ATLAS 2026.10 names and tactics.
- **FR-002**: vector YAML `atlas_mapping` gains the ids in the mapping table, nowhere else.
- **FR-003**: `AGENTIC_DEFAULTS[MULTI_AGENT] == [ASI07, ASI08]`; YAML overrides per the ASI table.
- **FR-004**: coverage docs, `benchmarks/README.md`, `coverage-comparison.md`,
  `benchmarks/results/baseline.json` and the README carry the regenerated counts.

## Success Criteria *(mandatory)*

- **SC-001**: `tests/unit/test_atlas_agent_techniques.py` passes, with one exact-set check per
  technique.
- **SC-002**: `benchmarks/atlas_coverage.py --strict` exits 0.

## Assumptions

- `AGENT_SPECIFIC_TECHNIQUES` stays at the 14 techniques of the October 2025 release. Adding the
  new ids would make the coverage gate fail on `AML.T0110.001` and `AML.T0118`, which no vector
  can honestly test. Overturned if the owner wants the set to follow ATLAS's "Agentic AI"
  platform tag; then those two need an exemption in the gate.
- `AML.T0110.001` and `AML.T0118` are in the enum with zero vectors, so the coverage reference
  shows them as gaps instead of hiding them. Overturned if the enum should hold only mapped ids.
- Only `AML.T0084` is added, not its sub-techniques (`.000` to `.003`); the scope names the
  parent. Overturned by a reviewer who wants `ma_topology_exfil` on `AML.T0084.003`.
- The ASI08 to ASI10 working definitions come from OWASP's AIVSS scoring data, since the
  Agentic Top 10 text is published as a PDF behind a form. Overturned if the published entries
  read differently; the YAML overrides then change.
- The elicitation overrides list ASI09 alone, following spec 089 (an override lists the specific
  id; an injection vector keeps ASI01). They lose the data-exfiltration default ASI02, since the
  agent misuses no tool there.
