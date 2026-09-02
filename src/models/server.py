"""Modèles utilisés pour les serveurs issus du CSV APM."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ObjServer(BaseModel):
    """Contrat Server propre au flux APM."""

    model_config = ConfigDict(extra="forbid")

    hostname: str
    operating_system: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    environment: str | None = None


class ServerAnomaly(BaseModel):
    """Anomalie Server sans exposition des valeurs sources."""

    model_config = ConfigDict(extra="forbid")

    error_type: Literal["SERVER_CONFLICT", "MISSING_SERVER_HOSTNAME"]
    hostname: str | None = None
    field: Literal["hostname", "operating_system", "environment"]
    distinct_value_count: int
