"""Canonical Server model built from the authoritative APM CSV."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from src.models.finding import Server


class ObjServer(Server):
    """APM Server representation without changing the Finding Server contract."""

    model_config = ConfigDict(extra="forbid")

    hostname: str
    operating_system: str | None = None


class ServerAnomaly(BaseModel):
    """Report-only Server anomaly without exposing conflicting source values."""

    model_config = ConfigDict(extra="forbid")

    error_type: Literal["SERVER_CONFLICT", "MISSING_SERVER_HOSTNAME"]
    hostname: str | None = None
    field: Literal["hostname", "operating_system", "environment"]
    distinct_value_count: int
