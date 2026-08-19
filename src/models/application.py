"""Canonical Application V1 models built from the RAW Finding CSV."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ObjApplication(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auid: str
    code_app: str | None = None
    trigram: str | None = None
    application_name: str | None = None
    appsec: str | None = None
    business_line: str | None = None
    production_domain_manager: str | None = None
    production_manager: str | None = None


class ApplicationAnomaly(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error_type: Literal["MISSING_AUID", "INVALID_AUID", "APPLICATION_CONFLICT"]
    row_index: int | None = None
    auid: str | None = None
    field: str
    values: list[Any] = Field(default_factory=list)
