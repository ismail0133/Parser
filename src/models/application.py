"""Canonical Application model built from the authoritative APM CSV."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ObjApplication(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auid: str
    trigram: str | None = None
    name: str | None = None


class ApplicationAnomaly(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error_type: Literal["APPLICATION_CONFLICT"]
    auid: str
    field: Literal["trigram", "name"]
    distinct_value_count: int
