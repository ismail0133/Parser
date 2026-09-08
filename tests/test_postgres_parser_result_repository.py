import json
from datetime import datetime, timezone
from uuid import UUID

import pytest

from src.persistence.postgres_repository import PostgresFindingRepository


class CapturingCursor:
    def __init__(self, connection):
        self.connection = connection
        self.current_result = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params):
        self.connection.calls.append((sql, params))
        if "RETURNING anomaly_id" in sql:
            self.current_result = (self.connection.anomaly_id,)

    def fetchone(self):
        return self.current_result


class CapturingConnection:
    def __init__(self, anomaly_id=901):
        self.calls = []
        self.anomaly_id = anomaly_id

    def cursor(self):
        return CapturingCursor(self)


PARSER_FINAL_STATUSES = (
    "SUCCESS",
    "SUCCESS_WITH_WARNINGS",
    "FAILED",
    "FAILED_AFTER_RETRIES",
)


@pytest.mark.parametrize("parser_status", PARSER_FINAL_STATUSES)
def test_finish_agent_run_preserves_each_parser_final_status(parser_status):
    connection = CapturingConnection()
    repository = PostgresFindingRepository(connection)
    ended_at = datetime(2026, 9, 8, 18, 30, tzinfo=timezone.utc)

    repository.finish_agent_run(71, ended_at, parser_status)

    assert connection.calls == [(
        "UPDATE agent_run SET ended_at = %s, run_status = %s WHERE agent_run_id = %s",
        (ended_at, parser_status, 71),
    )]


@pytest.mark.parametrize("parser_status", PARSER_FINAL_STATUSES)
def test_finish_pipeline_run_preserves_status_and_parser_output_count(parser_status):
    connection = CapturingConnection()
    repository = PostgresFindingRepository(connection)
    pipeline_run_id = UUID("00000000-0000-0000-0000-000000000123")
    ended_at = datetime(2026, 9, 8, 18, 31, tzinfo=timezone.utc)
    parser_output_findings = 417

    repository.finish_pipeline_run(
        pipeline_run_id,
        ended_at,
        parser_status,
        parser_output_findings,
    )

    assert connection.calls == [(
        "UPDATE pipeline_run SET ended_at = %s, run_status = %s, "
        "output_findings = %s WHERE pipeline_run_id = %s",
        (ended_at, parser_status, parser_output_findings, pipeline_run_id),
    )]


def test_insert_run_level_anomaly_keeps_context_ids_and_null_finding_id():
    connection = CapturingConnection(anomaly_id=902)
    repository = PostgresFindingRepository(connection)
    pipeline_run_id = UUID("00000000-0000-0000-0000-000000000123")
    details = {
        "row_index": 4,
        "rem_key_id": None,
        "field": "row",
        "value": None,
        "classification": "ERROR_NON_REMEDIABLE",
    }

    anomaly_id = repository.insert_anomaly({
        "pipeline_run_id": pipeline_run_id,
        "agent_run_id": 71,
        "finding_id": None,
        "anomaly_level": "ERROR",
        "code": "ROW_BUILD_ERROR",
        "message": "The source row could not produce a Finding.",
        "details": details,
    })

    assert anomaly_id == 902
    sql, params = connection.calls[0]
    assert sql == (
        "INSERT INTO anomaly (pipeline_run_id, agent_run_id, finding_id, anomaly_level, "
        "code, message, details) VALUES (%s, %s, %s, %s, %s, %s, %s) "
        "RETURNING anomaly_id"
    )
    assert params[:6] == (
        pipeline_run_id,
        71,
        None,
        "ERROR",
        "ROW_BUILD_ERROR",
        "The source row could not produce a Finding.",
    )
    assert json.loads(params[6]) == details


def test_insert_finding_anomaly_keeps_same_pipeline_agent_and_finding_ids():
    connection = CapturingConnection(anomaly_id=903)
    repository = PostgresFindingRepository(connection)
    pipeline_run_id = UUID("00000000-0000-0000-0000-000000000123")

    anomaly_id = repository.insert_anomaly({
        "pipeline_run_id": pipeline_run_id,
        "agent_run_id": 71,
        "finding_id": 812,
        "anomaly_level": "WARNING",
        "code": "KRI_NOT_COMPUTABLE",
        "message": "KRI cannot be computed.",
        "details": {"row_index": 9, "field": "KRI RAS 9"},
    })

    assert anomaly_id == 903
    _, params = connection.calls[0]
    assert params[0:3] == (pipeline_run_id, 71, 812)
    assert json.loads(params[6]) == {"row_index": 9, "field": "KRI RAS 9"}
