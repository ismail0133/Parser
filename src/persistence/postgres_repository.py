"""Parameterized PostgreSQL repository with no import-time connection."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, Sequence

from src.cleaning.finding_cleaner import normalize_string


APPLICATION_COLUMNS = (
    "auid", "code_app", "trigram", "application_name", "appsec", "business_line",
    "vital", "continuity_level", "application_manager", "domain_manager",
    "production_domain_manager", "production_manager",
)
APPLICATION_APM_COLUMNS = (
    "trigram", "application_name", "appsec", "business_line", "vital",
    "continuity_level", "application_manager", "domain_manager",
    "production_domain_manager", "production_manager",
)
SERVER_COLUMNS = (
    "hostname", "operating_system", "os_name", "os_version", "environment",
    "environment_detail", "sensitive", "authenticated_scan",
)
SERVER_APM_COLUMNS = (
    "operating_system", "os_name", "os_version",
)
SERVER_FINDING_COLUMNS = (
    "environment", "environment_detail", "sensitive", "authenticated_scan",
)
SERVER_SOURCE_APM = "apm"
SERVER_SOURCE_FINDING = "finding"
VULNERABILITY_COLUMNS = (
    "cve_code", "title", "description", "severity_level", "cvss_score",
)
FINDING_COLUMNS = (
    "pipeline_run_id", "application_id", "server_id", "vulnerability_id",
    "source_unique_id", "remediation_id", "application_auid", "as_of_date",
    "absolute_first_found_date", "last_found_date", "age_days", "sla_days", "overdue",
    "priority", "affected_component", "product", "extract_path", "severity_level",
    "business_line", "proposed_action", "ownership", "false_positive",
    "false_positive_to_confirm", "eta", "strategy_type", "strategy_description",
    "solution_links", "source_payload",
)
ARTIFACT_COLUMNS = (
    "artifact_type", "filename", "storage_path", "sha256",
    "pipeline_run_id", "agent_run_id", "row_count",
)
KRI_RAS9_SQL = """
WITH servers_by_hostname AS (
    SELECT
        BTRIM(s.hostname) AS hostname,
        BOOL_OR(
            s.sensitive IS TRUE
            AND s.authenticated_scan IS TRUE
        ) AS eligible,
        BOOL_OR(
            LOWER(f.severity_level) IN ('critical', 'very high')
            AND f.overdue IS TRUE
            AND f.false_positive IS NOT TRUE
        ) AS qualifying
    FROM finding AS f
    JOIN server AS s
        ON s.server_id = f.server_id
    WHERE f.pipeline_run_id = %s
      AND s.hostname IS NOT NULL
      AND BTRIM(s.hostname) <> ''
    GROUP BY BTRIM(s.hostname)
),
counts AS (
    SELECT
        COUNT(*) FILTER (WHERE eligible AND qualifying) AS numerator,
        COUNT(*) FILTER (WHERE eligible) AS denominator
    FROM servers_by_hostname
)
SELECT
    numerator,
    denominator,
    ROUND(100.0 * numerator / NULLIF(denominator, 0), 4) AS kri_percentage
FROM counts
"""


def _values(row: Mapping[str, Any], columns: Sequence[str]) -> tuple[Any, ...]:
    return tuple(row.get(column) for column in columns)


def _insert_sql(table: str, columns: Sequence[str], returning: str) -> str:
    placeholders = ", ".join(["%s"] * len(columns))
    return f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) RETURNING {returning}"


def normalize_hostname(value: Any) -> str | None:
    """Return the canonical hostname without changing its case."""
    if not isinstance(value, str):
        return None
    return normalize_string(value)


class ArtifactHashConflictError(ValueError):
    """Raised when one run/type/path points to two different file contents."""


class PostgresFindingRepository:
    def __init__(self, connection: Any):
        self.connection = connection

    def _insert(self, table: str, columns: Sequence[str], row: Mapping[str, Any], pk: str) -> Any:
        with self.connection.cursor() as cursor:
            cursor.execute(_insert_sql(table, columns, pk), _values(row, columns))
            return cursor.fetchone()[0]

    def create_pipeline_run(self, row: Mapping[str, Any]) -> Any:
        columns = ("pipeline_run_id", "started_at", "ended_at", "run_status", "source_filename",
                   "input_rows", "output_findings", "error_count", "warning_count")
        return self._insert("pipeline_run", columns, row, "pipeline_run_id")

    def get_or_create_agent(self, code: str, name: str = "Parser", execution_order: int = 1) -> Any:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT agent_id FROM agent WHERE agent_code = %s ORDER BY agent_id LIMIT 1", (code,))
            found = cursor.fetchone()
            if found:
                return found[0]
            cursor.execute(
                "INSERT INTO agent (agent_code, agent_name, execution_order, active) VALUES (%s, %s, %s, %s) RETURNING agent_id",
                (code, name, execution_order, True),
            )
            return cursor.fetchone()[0]

    def create_agent_run(self, row: Mapping[str, Any]) -> Any:
        columns = ("pipeline_run_id", "agent_id", "attempt_no", "started_at", "ended_at",
                   "run_status", "feedback_type", "feedback_message")
        return self._insert("agent_run", columns, row, "agent_run_id")

    def finish_agent_run(self, agent_run_id: Any, ended_at: Any, status: str) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE agent_run SET ended_at = %s, run_status = %s WHERE agent_run_id = %s",
                (ended_at, status, agent_run_id),
            )

    def finish_pipeline_run(
        self, pipeline_run_id: Any, ended_at: Any, status: str, output_findings: int,
    ) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE pipeline_run SET ended_at = %s, run_status = %s, output_findings = %s WHERE pipeline_run_id = %s",
                (ended_at, status, output_findings, pipeline_run_id),
            )

    def calculate_kri_ras9(self, pipeline_run_id: Any) -> dict[str, Any]:
        """Recalcule le KRI Parser pour un run PostgreSQL précis."""
        with self.connection.cursor() as cursor:
            cursor.execute(KRI_RAS9_SQL, (pipeline_run_id,))
            numerator, denominator, percentage = cursor.fetchone()
        return {
            "pipeline_run_id": str(pipeline_run_id),
            "numerator": numerator,
            "denominator": denominator,
            "kri_percentage": float(percentage) if percentage is not None else None,
        }

    def get_or_create_application(self, row: Mapping[str, Any]) -> Any:
        """Insert or synchronize the official non-NULL APM Application values."""
        auid = row.get("auid")
        if auid is None:
            return self._insert("application", APPLICATION_COLUMNS, row, "application_id")
        with self.connection.cursor() as cursor:
            cursor.execute(
                f"SELECT application_id, {', '.join(APPLICATION_COLUMNS)} "
                "FROM application WHERE auid = %s FOR UPDATE",
                (auid,),
            )
            found = cursor.fetchone()
            if found:
                application_id = found[0]
                existing = dict(zip(APPLICATION_COLUMNS, found[1:]))
                columns_to_update: list[str] = []
                for column in APPLICATION_APM_COLUMNS:
                    incoming_value = row.get(column)
                    existing_value = existing[column]
                    if incoming_value is not None and existing_value != incoming_value:
                        columns_to_update.append(column)
                if columns_to_update:
                    assignments = ", ".join(
                        f"{column} = %s" for column in columns_to_update
                    )
                    cursor.execute(
                        f"UPDATE application SET {assignments}, updated_at = CURRENT_TIMESTAMP "
                        "WHERE application_id = %s",
                        tuple(row.get(column) for column in columns_to_update)
                        + (application_id,),
                    )
                return application_id
            cursor.execute(
                _insert_sql("application", APPLICATION_COLUMNS, "application_id"),
                _values(row, APPLICATION_COLUMNS),
            )
            return cursor.fetchone()[0]

    def upsert_server(self, row: Mapping[str, Any], *, source: str) -> Any | None:
        """Upsert one canonical Server according to the source ownership rules."""
        if source not in {SERVER_SOURCE_APM, SERVER_SOURCE_FINDING}:
            raise ValueError(f"Unsupported Server source: {source}")

        hostname = normalize_hostname(row.get("hostname"))
        if hostname is None:
            return None

        prepared = {column: None for column in SERVER_COLUMNS}
        prepared["hostname"] = hostname
        if source == SERVER_SOURCE_APM:
            accepted_columns = SERVER_APM_COLUMNS
        else:
            accepted_columns = SERVER_APM_COLUMNS + SERVER_FINDING_COLUMNS
        for column in accepted_columns:
            prepared[column] = row.get(column)

        with self.connection.cursor() as cursor:
            cursor.execute(
                f"SELECT server_id, {', '.join(SERVER_COLUMNS)} "
                "FROM server WHERE hostname = %s FOR UPDATE",
                (hostname,),
            )
            found = cursor.fetchone()
            if not found:
                placeholders = ", ".join(["%s"] * len(SERVER_COLUMNS))
                cursor.execute(
                    f"INSERT INTO server ({', '.join(SERVER_COLUMNS)}) "
                    f"VALUES ({placeholders}) ON CONFLICT (hostname) DO NOTHING "
                    "RETURNING server_id",
                    _values(prepared, SERVER_COLUMNS),
                )
                inserted = cursor.fetchone()
                if inserted:
                    return inserted[0]
                # Another transaction inserted the canonical hostname after our
                # first SELECT. Lock that row and apply the same source policy.
                cursor.execute(
                    f"SELECT server_id, {', '.join(SERVER_COLUMNS)} "
                    "FROM server WHERE hostname = %s FOR UPDATE",
                    (hostname,),
                )
                found = cursor.fetchone()
                if not found:
                    raise RuntimeError(
                        f"Server upsert could not resolve hostname: {hostname}"
                    )

            server_id = found[0]
            existing = dict(zip(SERVER_COLUMNS, found[1:]))
            columns_to_update: list[str] = []
            if source == SERVER_SOURCE_APM:
                # APM is authoritative for OS data and may replace stale values.
                for column in SERVER_APM_COLUMNS:
                    incoming_value = prepared[column]
                    if incoming_value is not None and existing[column] != incoming_value:
                        columns_to_update.append(column)
            else:
                # Finding OS data is only a fallback when APM has not populated it.
                for column in SERVER_APM_COLUMNS:
                    if existing[column] is None and prepared[column] is not None:
                        columns_to_update.append(column)
                for column in SERVER_FINDING_COLUMNS:
                    incoming_value = prepared[column]
                    if incoming_value is not None and existing[column] != incoming_value:
                        columns_to_update.append(column)

            if columns_to_update:
                assignments = ", ".join(
                    f"{column} = %s" for column in columns_to_update
                )
                cursor.execute(
                    f"UPDATE server SET {assignments}, updated_at = CURRENT_TIMESTAMP "
                    "WHERE server_id = %s",
                    tuple(prepared[column] for column in columns_to_update)
                    + (server_id,),
                )
            return server_id

    def create_server(self, row: Mapping[str, Any]) -> Any | None:
        """Backward-compatible Finding entry point for canonical Server upserts."""
        return self.upsert_server(row, source=SERVER_SOURCE_FINDING)

    def upsert_application_server_relation(
        self, application_id: Any, server_id: Any,
    ) -> None:
        """Persist one canonical Application-Server pair idempotently."""
        if application_id is None or server_id is None:
            return
        with self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO application_server_relation (application_id, server_id) "
                "VALUES (%s, %s) ON CONFLICT (application_id, server_id) DO NOTHING",
                (application_id, server_id),
            )

    def get_or_create_vulnerability(self, row: Mapping[str, Any]) -> Any:
        cve = row.get("cve_code")
        if cve is None:
            return self._insert("vulnerability", VULNERABILITY_COLUMNS, row, "vulnerability_id")
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT vulnerability_id FROM vulnerability WHERE cve_code = %s", (cve,))
            found = cursor.fetchone()
            if found:
                return found[0]
            cursor.execute(_insert_sql("vulnerability", VULNERABILITY_COLUMNS, "vulnerability_id"),
                           _values(row, VULNERABILITY_COLUMNS))
            return cursor.fetchone()[0]

    def insert_finding(self, row: Mapping[str, Any]) -> Any:
        prepared = dict(row)
        prepared["source_payload"] = json.dumps(prepared["source_payload"], ensure_ascii=False)
        return self._insert("finding", FINDING_COLUMNS, prepared, "finding_id")

    def insert_anomaly(self, row: Mapping[str, Any]) -> Any:
        columns = ("pipeline_run_id", "agent_run_id", "finding_id", "anomaly_level", "code", "message", "details")
        prepared = dict(row)
        prepared["details"] = json.dumps(prepared.get("details"), ensure_ascii=False)
        return self._insert("anomaly", columns, prepared, "anomaly_id")

    def insert_artifact(self, row: Mapping[str, Any]) -> Any:
        """Insert one Artifact idempotently and reject content replacement."""
        pipeline_run_id = row.get("pipeline_run_id")
        if pipeline_run_id is None:
            raise ValueError("artifact.pipeline_run_id is required")
        for column in ("artifact_type", "filename", "storage_path", "sha256"):
            value = row.get(column)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"artifact.{column} is required")
        sha256 = row["sha256"]
        if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            raise ValueError("artifact.sha256 must contain 64 lowercase hexadecimal characters")
        row_count = row.get("row_count")
        if row_count is not None and (
            isinstance(row_count, bool) or not isinstance(row_count, int) or row_count < 0
        ):
            raise ValueError("artifact.row_count must be a non-negative integer or NULL")

        key = (pipeline_run_id, row["artifact_type"], row["storage_path"])
        select_sql = (
            "SELECT artifact_id, sha256 FROM artifact "
            "WHERE pipeline_run_id = %s AND artifact_type = %s AND storage_path = %s "
            "FOR UPDATE"
        )
        with self.connection.cursor() as cursor:
            cursor.execute(select_sql, key)
            found = cursor.fetchone()
            if found:
                return self._resolve_existing_artifact(found, row)

            placeholders = ", ".join(["%s"] * len(ARTIFACT_COLUMNS))
            cursor.execute(
                f"INSERT INTO artifact ({', '.join(ARTIFACT_COLUMNS)}) "
                f"VALUES ({placeholders}) "
                "ON CONFLICT (pipeline_run_id, artifact_type, storage_path) DO NOTHING "
                "RETURNING artifact_id",
                _values(row, ARTIFACT_COLUMNS),
            )
            inserted = cursor.fetchone()
            if inserted:
                return inserted[0]

            # A concurrent transaction may have inserted the same logical path.
            cursor.execute(select_sql, key)
            found = cursor.fetchone()
            if found:
                return self._resolve_existing_artifact(found, row)
            raise RuntimeError("Artifact upsert could not resolve the persisted row")

    @staticmethod
    def _resolve_existing_artifact(found: Sequence[Any], row: Mapping[str, Any]) -> Any:
        artifact_id, existing_sha256 = found
        if existing_sha256 != row["sha256"]:
            raise ArtifactHashConflictError(
                "ARTIFACT_HASH_CONFLICT: "
                f"pipeline_run_id={row['pipeline_run_id']} "
                f"artifact_type={row['artifact_type']} "
                f"storage_path={row['storage_path']} "
                f"existing_sha256={existing_sha256} incoming_sha256={row['sha256']}"
            )
        return artifact_id
