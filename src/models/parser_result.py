from typing import Any, Literal

from pydantic import BaseModel


class ParserResult(BaseModel):
    component: Literal["PARSER"] = "PARSER"
    status: Literal["SUCCESS", "SUCCESS_WITH_WARNINGS", "FAILED", "FAILED_AFTER_RETRIES"]
    input_file: str
    input_rows: int
    output_findings: int
    findings_artifact: str
    errors: int
    warnings: int
    infos: int
    retry_count: int
    max_attempts: int
    application_enrichment_status: Literal["SKIPPED_NO_SOURCE", "APPLIED"]
    anomalies_artifact: str
    analysis_report_artifact: str
    open_points: list[dict[str, Any]]
    duration_seconds: float
