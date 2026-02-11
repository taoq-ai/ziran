"""Attack vector and result models.

Defines the structure of attack vectors (what to test) and
attack results (what happened when we tested it).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from koan.domain.entities.phase import ScanPhase  # noqa: TC001


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


Severity = Literal["low", "medium", "high", "critical"]


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
    error: str | None = Field(
        default=None, description="Error message if the attack failed to execute"
    )
    owasp_mapping: list[OwaspLlmCategory] = Field(
        default_factory=list,
        description="OWASP Top 10 for LLM Applications categories for this finding",
    )
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
