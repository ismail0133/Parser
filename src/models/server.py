"""Canonical Server model built from the authoritative APM CSV."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

class ObjServer(BaseModel):
    """Dedicated APM Server contract, independent from Finding.Server."""

    model_config = ConfigDict(extra="forbid")

    hostname: str
    operating_system: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    environment: str | None = None


class ServerAnomaly(BaseModel):
    """Report-only Server anomaly without exposing conflicting source values."""

    model_config = ConfigDict(extra="forbid")

    error_type: Literal["SERVER_CONFLICT", "MISSING_SERVER_HOSTNAME"]
    hostname: str | None = None
    field: Literal["hostname", "operating_system", "environment"]
    distinct_value_count: int
