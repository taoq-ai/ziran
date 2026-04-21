"""Attack vector and result models.

Defines the structure of attack vectors (what to test) and
attack results (what happened when we tested it).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from ziran.domain.entities.phase import ScanPhase  # noqa: TC001


class TokenUsage(BaseModel):
    """Token consumption from a single LLM interaction or aggregated total."""

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)

    def __add__(self, other: TokenUsage) -> TokenUsage:
        return TokenUsage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
        )


class AttackCategory(StrEnum):
    """Categories of attack vectors."""

    PROMPT_INJECTION = "prompt_injection"
    TOOL_MANIPULATION = "tool_manipulation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    INDIRECT_INJECTION = "indirect_injection"
    MEMORY_POISONING = "memory_poisoning"
    CHAIN_OF_THOUGHT_MANIPULATION = "chain_of_thought_manipulation"
    MULTI_AGENT = "multi_agent"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    MODEL_DOS = "model_dos"


class OwaspLlmCategory(StrEnum):
    """OWASP Top 10 for Large Language Model Applications (2025).

    Standard taxonomy for classifying LLM security risks.
    See: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    """

    LLM01 = "LLM01"
    """Prompt Injection — direct or indirect manipulation of LLM input."""

    LLM02 = "LLM02"
    """Insecure Output Handling — insufficient validation of LLM output."""

    LLM03 = "LLM03"
    """Training Data Poisoning — manipulation of training/fine-tuning data."""

    LLM04 = "LLM04"
    """Model Denial of Service — resource-exhausting inputs."""

    LLM05 = "LLM05"
    """Supply Chain Vulnerabilities — compromised components or data."""

    LLM06 = "LLM06"
    """Sensitive Information Disclosure — leaking private data in responses."""

    LLM07 = "LLM07"
    """Insecure Plugin Design — unsafe tool/plugin interfaces."""

    LLM08 = "LLM08"
    """Excessive Agency — overly broad tool permissions or autonomy."""

    LLM09 = "LLM09"
    """Overreliance — blind trust in LLM output without verification."""

    LLM10 = "LLM10"
    """Unbounded Consumption — uncontrolled resource usage."""


#: Human-readable descriptions for each OWASP LLM category.
OWASP_LLM_DESCRIPTIONS: dict[OwaspLlmCategory, str] = {
    OwaspLlmCategory.LLM01: "Prompt Injection",
    OwaspLlmCategory.LLM02: "Insecure Output Handling",
    OwaspLlmCategory.LLM03: "Training Data Poisoning",
    OwaspLlmCategory.LLM04: "Model Denial of Service",
    OwaspLlmCategory.LLM05: "Supply Chain Vulnerabilities",
    OwaspLlmCategory.LLM06: "Sensitive Information Disclosure",
    OwaspLlmCategory.LLM07: "Insecure Plugin Design",
    OwaspLlmCategory.LLM08: "Excessive Agency",
    OwaspLlmCategory.LLM09: "Overreliance",
    OwaspLlmCategory.LLM10: "Unbounded Consumption",
}


class AtlasTactic(StrEnum):
    """MITRE ATLAS tactics (adversary goals against AI systems).

    Taxonomy for adversarial AI threats, parallel to MITRE ATT&CK for traditional
    enterprise systems. Snapshot pinned to the October 2025 ATLAS release
    (16 tactics).
    See: https://atlas.mitre.org/
    """

    AI_MODEL_ACCESS = "AML.TA0000"
    AI_ATTACK_STAGING = "AML.TA0001"
    RECONNAISSANCE = "AML.TA0002"
    RESOURCE_DEVELOPMENT = "AML.TA0003"
    INITIAL_ACCESS = "AML.TA0004"
    EXECUTION = "AML.TA0005"
    PERSISTENCE = "AML.TA0006"
    DEFENSE_EVASION = "AML.TA0007"
    DISCOVERY = "AML.TA0008"
    COLLECTION = "AML.TA0009"
    EXFILTRATION = "AML.TA0010"
    IMPACT = "AML.TA0011"
    PRIVILEGE_ESCALATION = "AML.TA0012"
    CREDENTIAL_ACCESS = "AML.TA0013"
    COMMAND_AND_CONTROL = "AML.TA0014"
    LATERAL_MOVEMENT = "AML.TA0015"


#: Human-readable names for each ATLAS tactic.
ATLAS_TACTIC_DESCRIPTIONS: dict[AtlasTactic, str] = {
    AtlasTactic.AI_MODEL_ACCESS: "AI Model Access",
    AtlasTactic.AI_ATTACK_STAGING: "AI Attack Staging",
    AtlasTactic.RECONNAISSANCE: "Reconnaissance",
    AtlasTactic.RESOURCE_DEVELOPMENT: "Resource Development",
    AtlasTactic.INITIAL_ACCESS: "Initial Access",
    AtlasTactic.EXECUTION: "Execution",
    AtlasTactic.PERSISTENCE: "Persistence",
    AtlasTactic.DEFENSE_EVASION: "Defense Evasion",
    AtlasTactic.DISCOVERY: "Discovery",
    AtlasTactic.COLLECTION: "Collection",
    AtlasTactic.EXFILTRATION: "Exfiltration",
    AtlasTactic.IMPACT: "Impact",
    AtlasTactic.PRIVILEGE_ESCALATION: "Privilege Escalation",
    AtlasTactic.CREDENTIAL_ACCESS: "Credential Access",
    AtlasTactic.COMMAND_AND_CONTROL: "Command and Control",
    AtlasTactic.LATERAL_MOVEMENT: "Lateral Movement",
}


class AtlasTechnique(StrEnum):
    """MITRE ATLAS techniques — how an adversary achieves a tactical goal.

    Snapshot pinned to the October 2025 ATLAS release. This enum includes
    the techniques referenced by at least one ZIRAN attack vector, plus all
    agent-specific techniques (see AGENT_SPECIFIC_TECHNIQUES).
    See: https://atlas.mitre.org/techniques/
    """

    # ── Reconnaissance (AML.TA0002) ──────────────────────────────────
    SEARCH_OPEN_TECHNICAL_DATABASES = "AML.T0000"
    SEARCH_OPEN_AI_VULNERABILITY_ANALYSIS = "AML.T0001"
    SEARCH_VICTIM_OWNED_WEBSITES = "AML.T0003"
    SEARCH_APPLICATION_REPOSITORIES = "AML.T0004"
    ACTIVE_SCANNING = "AML.T0006"
    GATHER_RAG_INDEXED_TARGETS = "AML.T0064"

    # ── Resource Development (AML.TA0003) ────────────────────────────
    ACQUIRE_PUBLIC_AI_ARTIFACTS = "AML.T0002"
    ACQUIRE_INFRASTRUCTURE = "AML.T0008"
    OBTAIN_CAPABILITIES = "AML.T0016"
    DEVELOP_CAPABILITIES = "AML.T0017"
    PUBLISH_POISONED_DATASETS = "AML.T0019"
    ESTABLISH_ACCOUNTS = "AML.T0021"
    PUBLISH_POISONED_MODELS = "AML.T0058"
    PUBLISH_HALLUCINATED_ENTITIES = "AML.T0060"
    LLM_PROMPT_CRAFTING = "AML.T0065"
    RETRIEVAL_CONTENT_CRAFTING = "AML.T0066"
    AI_SUPPLY_CHAIN_RUG_PULL = "AML.T0109"

    # ── Initial Access (AML.TA0004) ──────────────────────────────────
    AI_SUPPLY_CHAIN_COMPROMISE = "AML.T0010"
    VALID_ACCOUNTS = "AML.T0012"
    EVADE_AI_MODEL = "AML.T0015"
    EXPLOIT_PUBLIC_FACING_APPLICATION = "AML.T0049"
    PHISHING = "AML.T0052"

    # ── AI Model Access (AML.TA0000) ─────────────────────────────────
    AI_MODEL_INFERENCE_API_ACCESS = "AML.T0040"
    PHYSICAL_ENVIRONMENT_ACCESS = "AML.T0041"
    FULL_AI_MODEL_ACCESS = "AML.T0044"
    AI_ENABLED_PRODUCT_OR_SERVICE = "AML.T0047"

    # ── Execution (AML.TA0005) ───────────────────────────────────────
    USER_EXECUTION = "AML.T0011"
    COMMAND_AND_SCRIPTING_INTERPRETER = "AML.T0050"
    LLM_PROMPT_INJECTION = "AML.T0051"
    LLM_PROMPT_INJECTION_DIRECT = "AML.T0051.000"
    LLM_PROMPT_INJECTION_INDIRECT = "AML.T0051.001"
    AI_AGENT_TOOL_INVOCATION = "AML.T0053"

    # ── Persistence (AML.TA0006) ─────────────────────────────────────
    MANIPULATE_AI_MODEL = "AML.T0018"
    POISON_TRAINING_DATA = "AML.T0020"
    LLM_PROMPT_SELF_REPLICATION = "AML.T0061"
    RAG_POISONING = "AML.T0070"

    # ── Privilege Escalation (AML.TA0012) ────────────────────────────
    LLM_JAILBREAK = "AML.T0054"

    # ── Defense Evasion (AML.TA0007) ─────────────────────────────────
    LLM_TRUSTED_OUTPUT_COMPONENTS_MANIPULATION = "AML.T0067"
    LLM_TRUSTED_OUTPUT_CITATIONS = "AML.T0067.000"
    LLM_PROMPT_OBFUSCATION = "AML.T0068"
    FALSE_RAG_ENTRY_INJECTION = "AML.T0071"

    # ── Credential Access (AML.TA0013) ───────────────────────────────
    UNSECURED_CREDENTIALS = "AML.T0055"

    # ── Discovery (AML.TA0008) ───────────────────────────────────────
    DISCOVER_AI_ARTIFACTS = "AML.T0007"
    DISCOVER_AI_MODEL_ONTOLOGY = "AML.T0013"
    DISCOVER_AI_MODEL_FAMILY = "AML.T0014"
    DISCOVER_LLM_HALLUCINATIONS = "AML.T0062"
    DISCOVER_AI_MODEL_OUTPUTS = "AML.T0063"
    DISCOVER_LLM_SYSTEM_INFORMATION = "AML.T0069"
    DISCOVER_LLM_SYSTEM_PROMPT = "AML.T0069.002"

    # ── Collection (AML.TA0009) ──────────────────────────────────────
    COLLECTION = "AML.T0009"
    AI_ARTIFACT_COLLECTION = "AML.T0035"
    DATA_FROM_INFORMATION_REPOSITORIES = "AML.T0036"
    DATA_FROM_LOCAL_SYSTEM = "AML.T0037"

    # ── AI Attack Staging (AML.TA0001) ───────────────────────────────
    CREATE_PROXY_AI_MODEL = "AML.T0005"
    VERIFY_ATTACK = "AML.T0042"
    CRAFT_ADVERSARIAL_DATA = "AML.T0043"

    # ── Command and Control (AML.TA0014) ─────────────────────────────
    REVERSE_SHELL = "AML.T0072"

    # ── Exfiltration (AML.TA0010) ────────────────────────────────────
    EXFILTRATION_VIA_AI_INFERENCE_API = "AML.T0024"
    INFER_TRAINING_DATA_MEMBERSHIP = "AML.T0024.000"
    INVERT_AI_MODEL = "AML.T0024.001"
    EXTRACT_AI_MODEL = "AML.T0024.002"
    EXFILTRATION_VIA_CYBER_MEANS = "AML.T0025"
    EXTRACT_LLM_SYSTEM_PROMPT = "AML.T0056"
    LLM_DATA_LEAKAGE = "AML.T0057"

    # ── Impact (AML.TA0011) ──────────────────────────────────────────
    DENIAL_OF_AI_SERVICE = "AML.T0029"
    ERODE_AI_MODEL_INTEGRITY = "AML.T0031"
    COST_HARVESTING = "AML.T0034"
    SPAMMING_AI_SYSTEM_WITH_CHAFF_DATA = "AML.T0046"
    EXTERNAL_HARMS = "AML.T0048"
    EXTERNAL_HARMS_AI_IP_THEFT = "AML.T0048.004"
    ERODE_DATASET_INTEGRITY = "AML.T0059"
    GENERATE_DEEPFAKES = "AML.T0088"
    GENERATE_MALICIOUS_COMMANDS = "AML.T0102"


#: Human-readable name for each ATLAS technique.
ATLAS_TECHNIQUE_DESCRIPTIONS: dict[AtlasTechnique, str] = {
    AtlasTechnique.SEARCH_OPEN_TECHNICAL_DATABASES: "Search Open Technical Databases",
    AtlasTechnique.SEARCH_OPEN_AI_VULNERABILITY_ANALYSIS: "Search Open AI Vulnerability Analysis",
    AtlasTechnique.SEARCH_VICTIM_OWNED_WEBSITES: "Search Victim-Owned Websites",
    AtlasTechnique.SEARCH_APPLICATION_REPOSITORIES: "Search Application Repositories",
    AtlasTechnique.ACTIVE_SCANNING: "Active Scanning",
    AtlasTechnique.GATHER_RAG_INDEXED_TARGETS: "Gather RAG-Indexed Targets",
    AtlasTechnique.ACQUIRE_PUBLIC_AI_ARTIFACTS: "Acquire Public AI Artifacts",
    AtlasTechnique.ACQUIRE_INFRASTRUCTURE: "Acquire Infrastructure",
    AtlasTechnique.OBTAIN_CAPABILITIES: "Obtain Capabilities",
    AtlasTechnique.DEVELOP_CAPABILITIES: "Develop Capabilities",
    AtlasTechnique.PUBLISH_POISONED_DATASETS: "Publish Poisoned Datasets",
    AtlasTechnique.ESTABLISH_ACCOUNTS: "Establish Accounts",
    AtlasTechnique.PUBLISH_POISONED_MODELS: "Publish Poisoned Models",
    AtlasTechnique.PUBLISH_HALLUCINATED_ENTITIES: "Publish Hallucinated Entities",
    AtlasTechnique.LLM_PROMPT_CRAFTING: "LLM Prompt Crafting",
    AtlasTechnique.RETRIEVAL_CONTENT_CRAFTING: "Retrieval Content Crafting",
    AtlasTechnique.AI_SUPPLY_CHAIN_RUG_PULL: "AI Supply Chain Rug Pull",
    AtlasTechnique.AI_SUPPLY_CHAIN_COMPROMISE: "AI Supply Chain Compromise",
    AtlasTechnique.VALID_ACCOUNTS: "Valid Accounts",
    AtlasTechnique.EVADE_AI_MODEL: "Evade AI Model",
    AtlasTechnique.EXPLOIT_PUBLIC_FACING_APPLICATION: "Exploit Public-Facing Application",
    AtlasTechnique.PHISHING: "Phishing",
    AtlasTechnique.AI_MODEL_INFERENCE_API_ACCESS: "AI Model Inference API Access",
    AtlasTechnique.PHYSICAL_ENVIRONMENT_ACCESS: "Physical Environment Access",
    AtlasTechnique.FULL_AI_MODEL_ACCESS: "Full AI Model Access",
    AtlasTechnique.AI_ENABLED_PRODUCT_OR_SERVICE: "AI-Enabled Product or Service",
    AtlasTechnique.USER_EXECUTION: "User Execution",
    AtlasTechnique.COMMAND_AND_SCRIPTING_INTERPRETER: "Command and Scripting Interpreter",
    AtlasTechnique.LLM_PROMPT_INJECTION: "LLM Prompt Injection",
    AtlasTechnique.LLM_PROMPT_INJECTION_DIRECT: "LLM Prompt Injection: Direct",
    AtlasTechnique.LLM_PROMPT_INJECTION_INDIRECT: "LLM Prompt Injection: Indirect",
    AtlasTechnique.AI_AGENT_TOOL_INVOCATION: "AI Agent Tool Invocation",
    AtlasTechnique.MANIPULATE_AI_MODEL: "Manipulate AI Model",
    AtlasTechnique.POISON_TRAINING_DATA: "Poison Training Data",
    AtlasTechnique.LLM_PROMPT_SELF_REPLICATION: "LLM Prompt Self-Replication",
    AtlasTechnique.RAG_POISONING: "RAG Poisoning",
    AtlasTechnique.LLM_JAILBREAK: "LLM Jailbreak",
    AtlasTechnique.LLM_TRUSTED_OUTPUT_COMPONENTS_MANIPULATION: (
        "LLM Trusted Output Components Manipulation"
    ),
    AtlasTechnique.LLM_TRUSTED_OUTPUT_CITATIONS: "LLM Trusted Output Citations",
    AtlasTechnique.LLM_PROMPT_OBFUSCATION: "LLM Prompt Obfuscation",
    AtlasTechnique.FALSE_RAG_ENTRY_INJECTION: "False RAG Entry Injection",
    AtlasTechnique.UNSECURED_CREDENTIALS: "Unsecured Credentials",
    AtlasTechnique.DISCOVER_AI_ARTIFACTS: "Discover AI Artifacts",
    AtlasTechnique.DISCOVER_AI_MODEL_ONTOLOGY: "Discover AI Model Ontology",
    AtlasTechnique.DISCOVER_AI_MODEL_FAMILY: "Discover AI Model Family",
    AtlasTechnique.DISCOVER_LLM_HALLUCINATIONS: "Discover LLM Hallucinations",
    AtlasTechnique.DISCOVER_AI_MODEL_OUTPUTS: "Discover AI Model Outputs",
    AtlasTechnique.DISCOVER_LLM_SYSTEM_INFORMATION: "Discover LLM System Information",
    AtlasTechnique.DISCOVER_LLM_SYSTEM_PROMPT: "Discover LLM System Prompt",
    AtlasTechnique.COLLECTION: "Collection",
    AtlasTechnique.AI_ARTIFACT_COLLECTION: "AI Artifact Collection",
    AtlasTechnique.DATA_FROM_INFORMATION_REPOSITORIES: "Data from Information Repositories",
    AtlasTechnique.DATA_FROM_LOCAL_SYSTEM: "Data from Local System",
    AtlasTechnique.CREATE_PROXY_AI_MODEL: "Create Proxy AI Model",
    AtlasTechnique.VERIFY_ATTACK: "Verify Attack",
    AtlasTechnique.CRAFT_ADVERSARIAL_DATA: "Craft Adversarial Data",
    AtlasTechnique.REVERSE_SHELL: "Reverse Shell",
    AtlasTechnique.EXFILTRATION_VIA_AI_INFERENCE_API: "Exfiltration via AI Inference API",
    AtlasTechnique.INFER_TRAINING_DATA_MEMBERSHIP: "Infer Training Data Membership",
    AtlasTechnique.INVERT_AI_MODEL: "Invert AI Model",
    AtlasTechnique.EXTRACT_AI_MODEL: "Extract AI Model",
    AtlasTechnique.EXFILTRATION_VIA_CYBER_MEANS: "Exfiltration via Cyber Means",
    AtlasTechnique.EXTRACT_LLM_SYSTEM_PROMPT: "Extract LLM System Prompt",
    AtlasTechnique.LLM_DATA_LEAKAGE: "LLM Data Leakage",
    AtlasTechnique.DENIAL_OF_AI_SERVICE: "Denial of AI Service",
    AtlasTechnique.ERODE_AI_MODEL_INTEGRITY: "Erode AI Model Integrity",
    AtlasTechnique.COST_HARVESTING: "Cost Harvesting",
    AtlasTechnique.SPAMMING_AI_SYSTEM_WITH_CHAFF_DATA: "Spamming AI System with Chaff Data",
    AtlasTechnique.EXTERNAL_HARMS: "External Harms",
    AtlasTechnique.EXTERNAL_HARMS_AI_IP_THEFT: "External Harms: AI Intellectual Property Theft",
    AtlasTechnique.ERODE_DATASET_INTEGRITY: "Erode Dataset Integrity",
    AtlasTechnique.GENERATE_DEEPFAKES: "Generate Deepfakes",
    AtlasTechnique.GENERATE_MALICIOUS_COMMANDS: "Generate Malicious Commands",
}


#: Canonical parent tactic(s) for each ATLAS technique. Some techniques legitimately
#: span multiple tactics in the ATLAS data (e.g., LLM Jailbreak is both
#: Privilege Escalation and Defense Evasion).
ATLAS_TECHNIQUE_TO_TACTIC: dict[AtlasTechnique, list[AtlasTactic]] = {
    AtlasTechnique.SEARCH_OPEN_TECHNICAL_DATABASES: [AtlasTactic.RECONNAISSANCE],
    AtlasTechnique.SEARCH_OPEN_AI_VULNERABILITY_ANALYSIS: [AtlasTactic.RECONNAISSANCE],
    AtlasTechnique.SEARCH_VICTIM_OWNED_WEBSITES: [AtlasTactic.RECONNAISSANCE],
    AtlasTechnique.SEARCH_APPLICATION_REPOSITORIES: [AtlasTactic.RECONNAISSANCE],
    AtlasTechnique.ACTIVE_SCANNING: [AtlasTactic.RECONNAISSANCE],
    AtlasTechnique.GATHER_RAG_INDEXED_TARGETS: [AtlasTactic.RECONNAISSANCE],
    AtlasTechnique.ACQUIRE_PUBLIC_AI_ARTIFACTS: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.ACQUIRE_INFRASTRUCTURE: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.OBTAIN_CAPABILITIES: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.DEVELOP_CAPABILITIES: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.PUBLISH_POISONED_DATASETS: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.ESTABLISH_ACCOUNTS: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.PUBLISH_POISONED_MODELS: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.PUBLISH_HALLUCINATED_ENTITIES: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.LLM_PROMPT_CRAFTING: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.RETRIEVAL_CONTENT_CRAFTING: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.AI_SUPPLY_CHAIN_RUG_PULL: [AtlasTactic.RESOURCE_DEVELOPMENT],
    AtlasTechnique.AI_SUPPLY_CHAIN_COMPROMISE: [AtlasTactic.INITIAL_ACCESS],
    AtlasTechnique.VALID_ACCOUNTS: [AtlasTactic.INITIAL_ACCESS, AtlasTactic.PRIVILEGE_ESCALATION],
    AtlasTechnique.EVADE_AI_MODEL: [
        AtlasTactic.INITIAL_ACCESS,
        AtlasTactic.DEFENSE_EVASION,
        AtlasTactic.IMPACT,
    ],
    AtlasTechnique.EXPLOIT_PUBLIC_FACING_APPLICATION: [AtlasTactic.INITIAL_ACCESS],
    AtlasTechnique.PHISHING: [AtlasTactic.INITIAL_ACCESS, AtlasTactic.LATERAL_MOVEMENT],
    AtlasTechnique.AI_MODEL_INFERENCE_API_ACCESS: [AtlasTactic.AI_MODEL_ACCESS],
    AtlasTechnique.PHYSICAL_ENVIRONMENT_ACCESS: [AtlasTactic.AI_MODEL_ACCESS],
    AtlasTechnique.FULL_AI_MODEL_ACCESS: [AtlasTactic.AI_MODEL_ACCESS],
    AtlasTechnique.AI_ENABLED_PRODUCT_OR_SERVICE: [AtlasTactic.AI_MODEL_ACCESS],
    AtlasTechnique.USER_EXECUTION: [AtlasTactic.EXECUTION],
    AtlasTechnique.COMMAND_AND_SCRIPTING_INTERPRETER: [AtlasTactic.EXECUTION],
    AtlasTechnique.LLM_PROMPT_INJECTION: [AtlasTactic.EXECUTION],
    AtlasTechnique.LLM_PROMPT_INJECTION_DIRECT: [AtlasTactic.EXECUTION],
    AtlasTechnique.LLM_PROMPT_INJECTION_INDIRECT: [AtlasTactic.EXECUTION],
    AtlasTechnique.AI_AGENT_TOOL_INVOCATION: [
        AtlasTactic.EXECUTION,
        AtlasTactic.PRIVILEGE_ESCALATION,
    ],
    AtlasTechnique.MANIPULATE_AI_MODEL: [AtlasTactic.PERSISTENCE, AtlasTactic.AI_ATTACK_STAGING],
    AtlasTechnique.POISON_TRAINING_DATA: [
        AtlasTactic.PERSISTENCE,
        AtlasTactic.RESOURCE_DEVELOPMENT,
    ],
    AtlasTechnique.LLM_PROMPT_SELF_REPLICATION: [AtlasTactic.PERSISTENCE],
    AtlasTechnique.RAG_POISONING: [AtlasTactic.PERSISTENCE],
    AtlasTechnique.LLM_JAILBREAK: [
        AtlasTactic.PRIVILEGE_ESCALATION,
        AtlasTactic.DEFENSE_EVASION,
    ],
    AtlasTechnique.LLM_TRUSTED_OUTPUT_COMPONENTS_MANIPULATION: [AtlasTactic.DEFENSE_EVASION],
    AtlasTechnique.LLM_TRUSTED_OUTPUT_CITATIONS: [AtlasTactic.DEFENSE_EVASION],
    AtlasTechnique.LLM_PROMPT_OBFUSCATION: [AtlasTactic.DEFENSE_EVASION],
    AtlasTechnique.FALSE_RAG_ENTRY_INJECTION: [AtlasTactic.DEFENSE_EVASION],
    AtlasTechnique.UNSECURED_CREDENTIALS: [AtlasTactic.CREDENTIAL_ACCESS],
    AtlasTechnique.DISCOVER_AI_ARTIFACTS: [AtlasTactic.DISCOVERY],
    AtlasTechnique.DISCOVER_AI_MODEL_ONTOLOGY: [AtlasTactic.DISCOVERY],
    AtlasTechnique.DISCOVER_AI_MODEL_FAMILY: [AtlasTactic.DISCOVERY],
    AtlasTechnique.DISCOVER_LLM_HALLUCINATIONS: [AtlasTactic.DISCOVERY],
    AtlasTechnique.DISCOVER_AI_MODEL_OUTPUTS: [AtlasTactic.DISCOVERY],
    AtlasTechnique.DISCOVER_LLM_SYSTEM_INFORMATION: [AtlasTactic.DISCOVERY],
    AtlasTechnique.DISCOVER_LLM_SYSTEM_PROMPT: [AtlasTactic.DISCOVERY],
    AtlasTechnique.COLLECTION: [AtlasTactic.COLLECTION],
    AtlasTechnique.AI_ARTIFACT_COLLECTION: [AtlasTactic.COLLECTION],
    AtlasTechnique.DATA_FROM_INFORMATION_REPOSITORIES: [AtlasTactic.COLLECTION],
    AtlasTechnique.DATA_FROM_LOCAL_SYSTEM: [AtlasTactic.COLLECTION],
    AtlasTechnique.CREATE_PROXY_AI_MODEL: [AtlasTactic.AI_ATTACK_STAGING],
    AtlasTechnique.VERIFY_ATTACK: [AtlasTactic.AI_ATTACK_STAGING],
    AtlasTechnique.CRAFT_ADVERSARIAL_DATA: [AtlasTactic.AI_ATTACK_STAGING],
    AtlasTechnique.REVERSE_SHELL: [AtlasTactic.COMMAND_AND_CONTROL],
    AtlasTechnique.EXFILTRATION_VIA_AI_INFERENCE_API: [AtlasTactic.EXFILTRATION],
    AtlasTechnique.INFER_TRAINING_DATA_MEMBERSHIP: [AtlasTactic.EXFILTRATION],
    AtlasTechnique.INVERT_AI_MODEL: [AtlasTactic.EXFILTRATION],
    AtlasTechnique.EXTRACT_AI_MODEL: [AtlasTactic.EXFILTRATION],
    AtlasTechnique.EXFILTRATION_VIA_CYBER_MEANS: [AtlasTactic.EXFILTRATION],
    AtlasTechnique.EXTRACT_LLM_SYSTEM_PROMPT: [AtlasTactic.EXFILTRATION],
    AtlasTechnique.LLM_DATA_LEAKAGE: [AtlasTactic.EXFILTRATION],
    AtlasTechnique.DENIAL_OF_AI_SERVICE: [AtlasTactic.IMPACT],
    AtlasTechnique.ERODE_AI_MODEL_INTEGRITY: [AtlasTactic.IMPACT],
    AtlasTechnique.COST_HARVESTING: [AtlasTactic.IMPACT],
    AtlasTechnique.SPAMMING_AI_SYSTEM_WITH_CHAFF_DATA: [AtlasTactic.IMPACT],
    AtlasTechnique.EXTERNAL_HARMS: [AtlasTactic.IMPACT],
    AtlasTechnique.EXTERNAL_HARMS_AI_IP_THEFT: [AtlasTactic.IMPACT],
    AtlasTechnique.ERODE_DATASET_INTEGRITY: [AtlasTactic.IMPACT],
    AtlasTechnique.GENERATE_DEEPFAKES: [AtlasTactic.IMPACT],
    AtlasTechnique.GENERATE_MALICIOUS_COMMANDS: [AtlasTactic.IMPACT],
}


#: ATLAS techniques that are specific to generative-AI agents and LLM-based systems,
#: distinct from traditional ML attacks. Highlighted in the coverage dashboard so
#: readers can see at a glance which agent-focused techniques ZIRAN covers.
AGENT_SPECIFIC_TECHNIQUES: frozenset[AtlasTechnique] = frozenset(
    {
        AtlasTechnique.LLM_PROMPT_INJECTION,
        AtlasTechnique.LLM_PROMPT_INJECTION_DIRECT,
        AtlasTechnique.LLM_PROMPT_INJECTION_INDIRECT,
        AtlasTechnique.LLM_JAILBREAK,
        AtlasTechnique.AI_AGENT_TOOL_INVOCATION,
        AtlasTechnique.LLM_PROMPT_SELF_REPLICATION,
        AtlasTechnique.RAG_POISONING,
        AtlasTechnique.FALSE_RAG_ENTRY_INJECTION,
        AtlasTechnique.RETRIEVAL_CONTENT_CRAFTING,
        AtlasTechnique.GATHER_RAG_INDEXED_TARGETS,
        AtlasTechnique.LLM_PROMPT_OBFUSCATION,
        AtlasTechnique.LLM_TRUSTED_OUTPUT_COMPONENTS_MANIPULATION,
        AtlasTechnique.LLM_TRUSTED_OUTPUT_CITATIONS,
        AtlasTechnique.DISCOVER_LLM_SYSTEM_INFORMATION,
    }
)


class BusinessImpact(StrEnum):
    """Business impact categories aligned with Agent-SafetyBench taxonomy."""

    FINANCIAL_LOSS = "financial_loss"
    REPUTATION_DAMAGE = "reputation_damage"
    PROPERTY_LOSS = "property_loss"
    PRIVACY_VIOLATION = "privacy_violation"
    UNAUTHORIZED_ACTIONS = "unauthorized_actions"
    SYSTEM_COMPROMISE = "system_compromise"
    MISINFORMATION = "misinformation"


#: Human-readable descriptions for each business impact category.
BUSINESS_IMPACT_DESCRIPTIONS: dict[BusinessImpact, str] = {
    BusinessImpact.FINANCIAL_LOSS: "Financial Loss",
    BusinessImpact.REPUTATION_DAMAGE: "Reputation Damage",
    BusinessImpact.PROPERTY_LOSS: "Property Loss",
    BusinessImpact.PRIVACY_VIOLATION: "Privacy Violation",
    BusinessImpact.UNAUTHORIZED_ACTIONS: "Unauthorized Actions",
    BusinessImpact.SYSTEM_COMPROMISE: "System Compromise",
    BusinessImpact.MISINFORMATION: "Misinformation",
}


class HarmCategory(StrEnum):
    """Harm categories aligned with AgentHarm taxonomy.

    Classifies harmful multi-step task scenarios by the type of harm
    they attempt to elicit from the agent.
    See: https://huggingface.co/datasets/ai-safety-institute/AgentHarm
    """

    FRAUD = "fraud"
    """Financial fraud, scams, phishing, fake invoices."""

    CYBERCRIME = "cybercrime"
    """Hacking, credential theft, malware, unauthorized access."""

    HARASSMENT = "harassment"
    """Targeted harassment, bullying, doxxing, stalking."""

    DISINFORMATION = "disinformation"
    """Fake news, propaganda, social media manipulation."""

    ILLEGAL_SERVICES = "illegal_services"
    """Dark web markets, counterfeit documents, smuggling."""

    WEAPONS = "weapons"
    """Weapon acquisition, manufacturing, or distribution."""

    SUBSTANCE_ABUSE = "substance_abuse"
    """Drug synthesis, distribution, or promotion."""

    SEXUAL_CONTENT = "sexual_content"
    """Non-consensual sexual content, deepfakes."""

    SELF_HARM = "self_harm"
    """Self-harm instructions, suicide methods."""

    TERRORISM = "terrorism"
    """Attack planning, radicalization, extremist content."""

    CHILD_EXPLOITATION = "child_exploitation"
    """CSAM generation, grooming, exploitation."""


#: Human-readable descriptions for each harm category.
HARM_CATEGORY_DESCRIPTIONS: dict[HarmCategory, str] = {
    HarmCategory.FRAUD: "Financial Fraud",
    HarmCategory.CYBERCRIME: "Cybercrime",
    HarmCategory.HARASSMENT: "Harassment & Bullying",
    HarmCategory.DISINFORMATION: "Disinformation",
    HarmCategory.ILLEGAL_SERVICES: "Illegal Services",
    HarmCategory.WEAPONS: "Weapons",
    HarmCategory.SUBSTANCE_ABUSE: "Substance Abuse",
    HarmCategory.SEXUAL_CONTENT: "Sexual Content",
    HarmCategory.SELF_HARM: "Self-Harm",
    HarmCategory.TERRORISM: "Terrorism",
    HarmCategory.CHILD_EXPLOITATION: "Child Exploitation",
}


Severity = Literal["low", "medium", "high", "critical"]


# ── Business impact mapping ──────────────────────────────────────────

#: Base impacts for each attack category (always included).
_BASE_IMPACTS: dict[AttackCategory, list[BusinessImpact]] = {
    AttackCategory.PROMPT_INJECTION: [
        BusinessImpact.UNAUTHORIZED_ACTIONS,
        BusinessImpact.REPUTATION_DAMAGE,
    ],
    AttackCategory.TOOL_MANIPULATION: [
        BusinessImpact.UNAUTHORIZED_ACTIONS,
        BusinessImpact.SYSTEM_COMPROMISE,
    ],
    AttackCategory.PRIVILEGE_ESCALATION: [
        BusinessImpact.UNAUTHORIZED_ACTIONS,
        BusinessImpact.SYSTEM_COMPROMISE,
    ],
    AttackCategory.DATA_EXFILTRATION: [
        BusinessImpact.PRIVACY_VIOLATION,
        BusinessImpact.FINANCIAL_LOSS,
        BusinessImpact.REPUTATION_DAMAGE,
    ],
    AttackCategory.SYSTEM_PROMPT_EXTRACTION: [
        BusinessImpact.PROPERTY_LOSS,
        BusinessImpact.REPUTATION_DAMAGE,
    ],
    AttackCategory.INDIRECT_INJECTION: [
        BusinessImpact.UNAUTHORIZED_ACTIONS,
        BusinessImpact.REPUTATION_DAMAGE,
    ],
    AttackCategory.MEMORY_POISONING: [
        BusinessImpact.MISINFORMATION,
        BusinessImpact.REPUTATION_DAMAGE,
    ],
    AttackCategory.CHAIN_OF_THOUGHT_MANIPULATION: [
        BusinessImpact.MISINFORMATION,
        BusinessImpact.REPUTATION_DAMAGE,
    ],
    AttackCategory.MULTI_AGENT: [
        BusinessImpact.SYSTEM_COMPROMISE,
        BusinessImpact.UNAUTHORIZED_ACTIONS,
    ],
    AttackCategory.AUTHORIZATION_BYPASS: [
        BusinessImpact.UNAUTHORIZED_ACTIONS,
        BusinessImpact.PRIVACY_VIOLATION,
    ],
    AttackCategory.MODEL_DOS: [
        BusinessImpact.FINANCIAL_LOSS,
        BusinessImpact.REPUTATION_DAMAGE,
    ],
}

#: Extra impacts added when severity is critical (or critical/high for some).
_CRITICAL_EXTRAS: dict[AttackCategory, list[BusinessImpact]] = {
    AttackCategory.PROMPT_INJECTION: [BusinessImpact.SYSTEM_COMPROMISE],
    AttackCategory.TOOL_MANIPULATION: [BusinessImpact.FINANCIAL_LOSS],
    AttackCategory.PRIVILEGE_ESCALATION: [BusinessImpact.FINANCIAL_LOSS],
    AttackCategory.INDIRECT_INJECTION: [BusinessImpact.FINANCIAL_LOSS],
    AttackCategory.MEMORY_POISONING: [BusinessImpact.UNAUTHORIZED_ACTIONS],
    AttackCategory.MULTI_AGENT: [BusinessImpact.FINANCIAL_LOSS],
    AttackCategory.AUTHORIZATION_BYPASS: [
        BusinessImpact.FINANCIAL_LOSS,
        BusinessImpact.SYSTEM_COMPROMISE,
    ],
    AttackCategory.MODEL_DOS: [BusinessImpact.SYSTEM_COMPROMISE],
}

#: Categories where "high" severity also triggers critical extras.
_HIGH_ALSO_ESCALATES: frozenset[AttackCategory] = frozenset(
    {
        AttackCategory.PRIVILEGE_ESCALATION,
        AttackCategory.AUTHORIZATION_BYPASS,
    }
)


def get_business_impacts(
    category: AttackCategory,
    severity: Severity,
) -> list[BusinessImpact]:
    """Derive business impact categories from an attack category and severity.

    Returns a deterministic list of :class:`BusinessImpact` values.  Higher
    severity may add additional impacts on top of the base set.
    """
    impacts = list(_BASE_IMPACTS.get(category, []))

    escalate = severity == "critical" or (severity == "high" and category in _HIGH_ALSO_ESCALATES)
    if escalate:
        for extra in _CRITICAL_EXTRAS.get(category, []):
            if extra not in impacts:
                impacts.append(extra)

    return impacts


class AttackPrompt(BaseModel):
    """A single prompt template within an attack vector.

    Each attack vector can have multiple prompts that are sent
    in sequence or chosen based on context.
    """

    template: str = Field(description="Prompt template with {variable} placeholders")
    variables: dict[str, str] = Field(
        default_factory=dict,
        description="Default variable values for the template",
    )
    success_indicators: list[str] = Field(
        default_factory=list,
        description="Strings/patterns that indicate the attack succeeded",
    )
    failure_indicators: list[str] = Field(
        default_factory=list,
        description="Strings/patterns that indicate the attack was blocked",
    )


class AttackVector(BaseModel):
    """A specific attack technique to test against an agent.

    Attack vectors are loaded from YAML files and contain both
    metadata and the actual prompt templates used for testing.
    """

    id: str = Field(description="Unique vector identifier (e.g., 'pi_basic_override')")
    name: str = Field(description="Human-readable attack name")
    category: AttackCategory
    target_phase: ScanPhase
    description: str
    severity: Severity
    prompts: list[AttackPrompt] = Field(
        default_factory=list, description="Prompt templates for this attack"
    )
    tags: list[str] = Field(default_factory=list, description="Searchable tags")
    references: list[str] = Field(
        default_factory=list, description="Links to research/documentation"
    )
    owasp_mapping: list[OwaspLlmCategory] = Field(
        default_factory=list,
        description="OWASP Top 10 for LLM Applications categories this vector maps to",
    )
    atlas_mapping: list[AtlasTechnique] = Field(
        default_factory=list,
        description="MITRE ATLAS techniques this vector exercises (October 2025 snapshot)",
    )
    protocol_filter: list[str] = Field(
        default_factory=list,
        description="Protocols this vector applies to (empty = all). Values: rest, openai, mcp, a2a.",
    )
    tactic: str = Field(
        default="single",
        description="Execution tactic: single (default), crescendo, context_buildup, persona_shift, "
        "distraction, few_shot, refusal_suppression, hypothetical, role_play, language_switch, code_mode.",
    )
    harm_category: HarmCategory | None = Field(
        default=None,
        description="AgentHarm-aligned harm category for harmful task scenarios.",
    )

    @property
    def is_critical(self) -> bool:
        """Check if this is a critical-severity vector."""
        return self.severity == "critical"

    @property
    def prompt_count(self) -> int:
        """Number of prompt templates in this vector."""
        return len(self.prompts)


class AttackResult(BaseModel):
    """Result of executing an attack vector against an agent.

    Captures whether the attack succeeded, the evidence collected,
    and the agent's raw response for analysis.
    """

    vector_id: str = Field(description="ID of the attack vector that was executed")
    vector_name: str = Field(description="Human-readable name of the vector")
    category: AttackCategory
    severity: Severity
    successful: bool = Field(description="Whether the attack achieved its objective")
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Evidence supporting the success/failure determination"
    )
    agent_response: str | None = Field(default=None, description="Raw agent response text")
    extracted_data: dict[str, Any] | None = Field(
        default=None, description="Any data extracted during the attack"
    )
    prompt_used: str | None = Field(default=None, description="The actual prompt that was sent")
    encoding_applied: str | None = Field(
        default=None, description="Encoding/obfuscation type applied to the prompt (if any)"
    )
    error: str | None = Field(
        default=None, description="Error message if the attack failed to execute"
    )
    owasp_mapping: list[OwaspLlmCategory] = Field(
        default_factory=list,
        description="OWASP Top 10 for LLM Applications categories for this finding",
    )
    atlas_mapping: list[AtlasTechnique] = Field(
        default_factory=list,
        description="MITRE ATLAS techniques exercised by this finding (copied from vector)",
    )
    business_impact: list[BusinessImpact] = Field(
        default_factory=list,
        description="Business impact categories derived from attack category and severity",
    )
    harm_category: HarmCategory | None = Field(
        default=None,
        description="AgentHarm-aligned harm category if this was a harmful task scenario.",
    )
    quality_score: float | None = Field(
        default=None,
        description="StrongREJECT-style composite quality score (0.0-1.0) from the LLM judge, "
        "computed as (1 - refusal) * (specificity + convincingness) / 2.",
    )
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
