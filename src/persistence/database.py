"""PostgreSQL configuration and connection factory."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class PostgresConfig:
    host: str
    port: int
    dbname: str
    user: str
    password: str
    sslmode: str | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "PostgresConfig":
        values = os.environ if environ is None else environ
        required = ("POSTGRES_HOST", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")
        missing = [name for name in required if not values.get(name)]
        if missing:
            raise ValueError("Missing PostgreSQL environment variables: " + ", ".join(missing))
        try:
            port = int(values.get("POSTGRES_PORT", "5432"))
        except ValueError as exc:
            raise ValueError("POSTGRES_PORT must be an integer") from exc
        return cls(
            host=values["POSTGRES_HOST"], port=port, dbname=values["POSTGRES_DB"],
            user=values["POSTGRES_USER"], password=values["POSTGRES_PASSWORD"],
            sslmode=values.get("POSTGRES_SSLMODE") or None,
        )

    def connection_kwargs(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "host": self.host, "port": self.port, "dbname": self.dbname,
            "user": self.user, "password": self.password,
        }
        if self.sslmode:
            result["sslmode"] = self.sslmode
        return result


def connect(config: PostgresConfig | None = None):
    """Open a connection only when explicitly called; importing is offline-safe."""
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("PostgreSQL loading requires psycopg; install project requirements") from exc
    return psycopg.connect(**(config or PostgresConfig.from_env()).connection_kwargs())
