"""Modèles utilisés pour les applications issues du CSV APM."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ObjApplication(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auid: str
    trigram: str | None = None
    name: str | None = None
    business_line: str | None = None
    appsec: str | None = None
    vital: str | None = None
    continuity_level: str | None = None
    application_manager: str | None = None
    domain_manager: str | None = None
    production_manager: str | None = None
    production_domain_manager: str | None = None


class ApplicationAnomaly(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error_type: Literal["APPLICATION_CONFLICT"]
    auid: str
    field: Literal[
        "trigram",
        "name",
        "business_line",
        "appsec",
        "vital",
        "continuity_level",
        "application_manager",
        "domain_manager",
        "production_manager",
        "production_domain_manager",
    ]
    distinct_value_count: int
