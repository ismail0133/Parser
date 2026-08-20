"""Parameterized PostgreSQL repository with no import-time connection."""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence


APPLICATION_COLUMNS = (
    "auid", "trigram", "application_name", "appsec", "vital", "cis", "business_line",
)
SERVER_COLUMNS = (
    "hostname", "operating_system", "os_name", "os_version", "environment",
    "environment_detail", "sensitive", "authenticated_scan",
)
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


def _values(row: Mapping[str, Any], columns: Sequence[str]) -> tuple[Any, ...]:
    return tuple(row.get(column) for column in columns)


def _insert_sql(table: str, columns: Sequence[str], returning: str) -> str:
    placeholders = ", ".join(["%s"] * len(columns))
    return f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) RETURNING {returning}"


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

    def get_or_create_application(self, row: Mapping[str, Any]) -> Any:
        auid = row.get("auid")
        if auid is None:
            return self._insert("application", APPLICATION_COLUMNS, row, "application_id")
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT application_id FROM application WHERE auid = %s", (auid,))
            found = cursor.fetchone()
            if found:
                return found[0]
            cursor.execute(
                _insert_sql("application", APPLICATION_COLUMNS, "application_id"),
                _values(row, APPLICATION_COLUMNS),
            )
            return cursor.fetchone()[0]

    def create_server(self, row: Mapping[str, Any]) -> Any:
        return self._insert("server", SERVER_COLUMNS, row, "server_id")

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
        columns = ("artifact_type", "filename", "storage_path", "sha256")
        return self._insert("artifact", columns, row, "artifact_id")
