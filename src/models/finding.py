from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class Server(BaseModel):
    os_name: str | None = None
    os_version: str | None = None
    environment_detail: str | None = None
    environment: str | None = None
    sensitive: bool = False
    authenticated_scan: bool | None = True


class Application(BaseModel):
    auid: str | None = None
    trigram: str | None = None
    name: str | None = None
    appsec: str | None = None
    vital: bool | str | None = None
    cis: bool | None = None


class CveDetail(BaseModel):
    title: str | None = None
    solution_links: str | None = None


class RemediationStrategy(BaseModel):
    description: str | None = None
    strategy_type: str | None = None  # Responsibility: ANALYST.
    ownership_main: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unique_id: str | None = None
    as_of_date: date | None = None
    remediation_id: str | None = None
    hostname: str | None = None
    server: Server
    application: Application
    cve: str | None = None
    cve_detail: CveDetail
    priority: int | None = None
    affected_component: str | None = None
    affected_product: str | None = None
    target: str | None = None
    first_detection: date | None = None
    last_detection: date | None = None
    age: int | None = None
    sla: int | None = None
    overdue: bool | None = None
    business_line: str | None = None
    severity_level: str | None = None
    proposed_action: str | None = None
    ownership: str | None = None  # RAW Proposed Owner; automatic APS/ADM routing is deferred to V2.
    remediation_strategy: RemediationStrategy
    false_positive: bool = False
    false_positive_to_confirm: bool = False
    eta: date | None = None


class Anomaly(BaseModel):
    row_index: int
    rem_key_id: str | None = None
    field: str
    value: Any = None
    severity: Literal["INFO", "WARNING", "ERROR"]
    error_type: str
    message: str
    classification: Literal[
        "ERROR_REMEDIABLE", "ERROR_NON_REMEDIABLE", "WARNING", "INFO", "TO_VALIDATE"
    ] | None = None
