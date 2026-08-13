from typing import Any, Literal

from pydantic import BaseModel, Field


class AgentInput(BaseModel):
    file: str
    rows: int = 0


class AgentParserSummary(BaseModel):
    status: Literal["SUCCESS", "SUCCESS_WITH_WARNINGS", "FAILED", "FAILED_AFTER_RETRIES"]
    output_findings: int = 0
    errors: int = 0
    warnings: int = 0
    retry_count: int = 0
    max_attempts: int = 3


class AgentKriSummary(BaseModel):
    mismatches: int = 0
    classification: str | None = None
    distribution: dict[str, int] = Field(default_factory=dict)
    automatically_correctable: int = 0
    percentage: float | None = None
    business_target: str = "< 30%"
    business_target_met: bool | None = None
    source_inconsistencies: int = 0


class ParserAgentResult(BaseModel):
    agent: Literal["PARSER"] = "PARSER"
    agent_version: Literal["V0"] = "V0"
    status: Literal["SUCCESS", "SUCCESS_WITH_WARNINGS", "FAILED"]
    input: AgentInput
    parser: AgentParserSummary | None = None
    kri: AgentKriSummary = Field(default_factory=AgentKriSummary)
    application_enrichment: dict[str, str] = Field(
        default_factory=lambda: {"status": "SKIPPED_NO_SOURCE"}
    )
    dependencies: dict[str, str] = Field(default_factory=lambda: {
        "cib_apm": "WAITING_FOR_SOURCE",
        "postgresql": "NOT_CONFIGURED",
        "llm_api": "NOT_CONFIGURED",
    })
    llm_status: Literal["NOT_CONFIGURED"] = "NOT_CONFIGURED"
    persistence_status: Literal["LOCAL_ONLY"] = "LOCAL_ONLY"
    requires_business_validation: bool = False
    open_points: list[str] = Field(default_factory=list)
    artifacts: dict[str, str] = Field(default_factory=dict)
    next_action: Literal["CONTINUE", "STOP"]
    reason: str | None = None
    error_message: str | None = None
