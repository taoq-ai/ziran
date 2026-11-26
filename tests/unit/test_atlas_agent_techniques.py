"""MITRE ATLAS agent techniques and OWASP Agentic ASI08-ASI10 mappings (spec 109).

Ids, names and tactics are from ATLAS data release 2026.10
(mitre-atlas/atlas-data ``dist/v6/ATLAS-2026.10.yaml``). The expected vector sets mirror the
mapping table in ``specs/109-atlas-agent-mappings/spec.md``: a technique appears on these
vectors and on no other.
"""

from __future__ import annotations

import pytest

from ziran.application.attacks.library import AGENTIC_DEFAULTS, AttackLibrary
from ziran.domain.entities.attack import (
    ATLAS_TECHNIQUE_DESCRIPTIONS,
    ATLAS_TECHNIQUE_TO_TACTIC,
    AtlasTactic,
    AtlasTechnique,
    AttackCategory,
    OwaspAgenticCategory,
)

T, TA, ASI = AtlasTechnique, AtlasTactic, OwaspAgenticCategory

# id -> (name, tactics) as published in ATLAS 2026.10.
PUBLISHED: dict[str, tuple[str, list[AtlasTactic]]] = {
    "AML.T0080": ("AI Agent Context Poisoning", [TA.PERSISTENCE]),
    "AML.T0080.000": ("AI Agent Context Poisoning: Memory", [TA.PERSISTENCE]),
    "AML.T0080.001": ("AI Agent Context Poisoning: Thread", [TA.PERSISTENCE]),
    "AML.T0081": ("Modify AI Agent Configuration", [TA.PERSISTENCE, TA.DEFENSE_EVASION]),
    "AML.T0084": ("Discover AI Agent Configuration", [TA.DISCOVERY]),
    "AML.T0086": ("Exfiltration via AI Agent Tool Invocation", [TA.EXFILTRATION]),
    "AML.T0110": ("AI Agent Tool Poisoning", [TA.PERSISTENCE]),
    "AML.T0110.000": ("AI Agent Tool Poisoning: Definition and Instructions", [TA.PERSISTENCE]),
    "AML.T0110.001": ("AI Agent Tool Poisoning: Implementation", [TA.PERSISTENCE]),
    "AML.T0110.002": ("AI Agent Tool Poisoning: Runtime Response", [TA.PERSISTENCE]),
    "AML.T0118": ("Autonomous AI Agent Communication", [TA.AI_ATTACK_STAGING]),
    "AML.T0133": ("Discover AI Agent Runtime Capabilities", [TA.DISCOVERY]),
}

MEMORY = {
    "mp_cross_session_persistence",
    "mp_memory_key_injection",
    "mt_crescendo_memory_poison",
    "ma_memory_poisoning",
}
THREAD = {
    "mp_false_history",
    "mp_conversation_rewrite",
    "mp_context_anchoring",
    "mp_instruction_persistence",
    "mp_identity_override",
    "mp_delayed_trigger",
    "mp_summary_manipulation",
    "ma_state_injection",
    "a2a_context_pollution",
}
DEFINITION = {
    "mcp_tool_desc_injection",
    "mcp_param_desc_injection",
    "mcp_preauth_claim",
    "mcp_security_check_disguise",
    "mcp_compliance_override",
    "mcp_param_substitution",
    "mcp_default_override",
    "mcp_shadow_redirect",
    "mcp_desc_base64_encoded",
    "mcp_desc_unicode_obfuscation",
    "mcp_desc_markdown_hidden",
    "mcp_desc_system_prompt_override",
    "mcp_desc_role_impersonation",
    "mcp_desc_urgency_pressure",
    "mcp_desc_multi_language",
    "mcp_desc_jailbreak_template",
    "mcp_desc_unicode_smuggle",
    "mcp_param_hidden_field",
    "mcp_param_type_confusion",
    "mcp_param_enum_escape",
    "mcp_param_sql_injection_hint",
    "mcp_param_path_traversal_hint",
    "mcp_param_command_injection_hint",
    "mcp_param_schema_overflow",
    "mcp_chain_read_then_exfil",
    "mcp_chain_escalation_ladder",
    "mcp_chain_tool_confusion",
    "mcp_chain_circular_delegation",
    "mcp_exfil_dns",
    "mcp_exfil_url_encoding",
    "mcp_exfil_steganographic",
    "mcp_exfil_delayed_batch",
    "mcp_exfil_log_channel",
    "mcp_trigger_user_specific",
    "mcp_trigger_time_delayed",
    "mcp_trigger_data_dependent",
    "mcp_trigger_context_dependent",
    "mcp_delayed_payload_activation",
    "mcp_multiserver_trust_pivot",
    "mcp_multiserver_credential_theft",
    "mcp_multiserver_config_poisoning",
    "mcp_privesc_consent_phishing",
    "mcp_privesc_scope_widening",
    "mcp_privesc_capability_claim",
    "mcp_privesc_env_var_access",
    "mcp_lifecycle_init_poison",
    "mcp_lifecycle_dynamic_redefinition",
    "mcp_filesystem_escape",
    "mcp_git_history_exfil",
    "mcp_database_dump",
    "mcp_browser_cookie_theft",
    "mcp_slack_impersonation",
    "mcp_email_bcc_injection",
    "mcp_cloud_iam_escalation",
    "mcp_kubernetes_escape",
    "mcp_social_fake_update",
    "mcp_social_reward_promise",
    "mcp_evasion_token_splitting",
    "mcp_evasion_semantic_paraphrase",
    "mcp_evasion_few_shot_examples",
    "mcp_evasion_chain_of_thought",
    "mcp_persist_config_write",
    "mcp_persist_cron_injection",
    "mcp_persist_ssh_key_injection",
    "mcp_dos_recursive_tool",
    "mcp_dos_api_abuse",
    "mcp_notification_hijack",
    "mcp_env_variable_exfil",
    "mcp_tool_rename_confusion",
    "mcp_supply_chain_typosquat",
    "sc_malicious_plugin_manifest",
    "sc_typosquatted_tool",
}
RUNTIME_RESPONSE = {
    "mcp_response_instruction_injection",
    "mcp_response_fake_error",
    "mcp_response_data_poisoning",
    "mcp_response_context_window_stuffing",
    "mcp_response_credential_harvest",
    "mcp_cross_tool_permission_launder",
    "mcp_jsonrpc_injection",
    "mcp_social_fake_update",
    "mcp_social_helpdesk_impersonation",
    "mcp_srv_roots_filesystem_or_home",
    "mcp_srv_roots_credential_folders",
}

EXPECTED: dict[AtlasTechnique, set[str]] = {
    T("AML.T0080"): MEMORY | THREAD,
    T("AML.T0080.000"): MEMORY,
    T("AML.T0080.001"): THREAD,
    T("AML.T0081"): {
        "pe_config_override",
        "ii_chat_tool_config",
        "mcp_persist_config_write",
        "agt26_mcp_stdio_config_command",
        "agt26_mcp_flow_embedded_server_config",
    },
    T("AML.T0084"): {
        "a2a_card_enumeration",
        "a2a_extended_card_leak",
        "spe_json_dump",
        "mt_code_json_schema",
        "mt_fewshot_format_priming",
        "de_summary_extraction",
        "ma_topology_exfil",
    },
    T("AML.T0086"): {
        "de_tool_based_exfil",
        "de_url_exfil",
        "ii_email_exfil_reply",
        "ii_email_tool_send",
        "ii_email_tool_forward",
        "ii_api_exfil_webhook",
        "ii_db_exfil_trigger",
        "ii_notification_exfil",
        "mt_context_tool_chain",
        "mcp_chain_read_then_exfil",
        "mcp_exfil_dns",
        "mcp_exfil_url_encoding",
        "mcp_exfil_steganographic",
        "mcp_exfil_delayed_batch",
        "mcp_exfil_log_channel",
        "mcp_email_bcc_injection",
        "mcp_multi_server_data_relay",
        "mcp_env_variable_exfil",
        "mcp_privesc_env_var_access",
        "mcp_param_substitution",
        "mcp_composite_reconnaissance_exfil",
        "mcp_multiserver_credential_theft",
        "mcp_response_credential_harvest",
    },
    T("AML.T0110"): DEFINITION | RUNTIME_RESPONSE,
    T("AML.T0110.000"): DEFINITION,
    T("AML.T0110.001"): set(),
    T("AML.T0110.002"): RUNTIME_RESPONSE,
    T("AML.T0118"): set(),
    T("AML.T0133"): {
        "pe_permission_probing",
        "tm_tool_name_spoofing",
        "mt_crescendo_tool_disclosure",
        "mt_context_tool_chain",
        "mt_context_permission_boundary",
    },
}


@pytest.mark.unit
@pytest.mark.parametrize("technique_id", sorted(PUBLISHED))
def test_technique_matches_the_atlas_release(technique_id: str) -> None:
    name, tactics = PUBLISHED[technique_id]
    technique = AtlasTechnique(technique_id)
    assert ATLAS_TECHNIQUE_DESCRIPTIONS[technique] == name
    assert ATLAS_TECHNIQUE_TO_TACTIC[technique] == tactics


@pytest.mark.unit
@pytest.mark.parametrize("technique", sorted(EXPECTED), ids=str)
def test_technique_sits_only_on_vectors_that_test_it(
    shared_attack_library: AttackLibrary, technique: AtlasTechnique
) -> None:
    found = {v.id for v in shared_attack_library.get_attacks_by_atlas(technique)}
    assert found == EXPECTED[technique]


@pytest.mark.unit
def test_every_mapped_vector_exists(shared_attack_library: AttackLibrary) -> None:
    known = {v.id for v in shared_attack_library.vectors}
    assert set().union(*EXPECTED.values()) <= known


@pytest.mark.unit
class TestAgenticDefaults:
    def test_multi_agent_default_adds_cascading_failures(self) -> None:
        assert AGENTIC_DEFAULTS[AttackCategory.MULTI_AGENT] == [ASI.ASI07, ASI.ASI08]

    def test_builtin_asi08_to_asi10_mappings(self, shared_attack_library: AttackLibrary) -> None:
        mapped = {v.id: v.owasp_agentic_mapping for v in shared_attack_library.vectors}
        assert mapped["ma_delegation_chain_exploit"] == [ASI.ASI07, ASI.ASI08]
        assert mapped["ma_topology_exfil"] == [ASI.ASI07]
        assert mapped["ma_inter_agent_eavesdrop"] == [ASI.ASI07]
        assert mapped["ma_trust_escalation"] == [ASI.ASI07, ASI.ASI10]
        assert mapped["a2a_card_forgery_impersonation"] == [ASI.ASI01, ASI.ASI07, ASI.ASI10]
        for vid in (
            "mcp_srv_elicit_api_key",
            "mcp_srv_elicit_password_otp",
            "mcp_srv_elicit_overbroad_identity",
            "mcp_srv_elicit_overbroad_payment",
        ):
            assert mapped[vid] == [ASI.ASI09], vid
