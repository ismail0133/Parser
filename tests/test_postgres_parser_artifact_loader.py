import json
from uuid import UUID

import pytest

from scripts.load_obj_findings_to_postgres import load_transaction, main
from src.models.finding import Anomaly
from src.models.parser_result import ParserResult


PARSER_FINAL_STATUSES = (
    "SUCCESS",
    "SUCCESS_WITH_WARNINGS",
    "FAILED",
    "FAILED_AFTER_RETRIES",
)


def parser_result(**overrides) -> ParserResult:
    payload = {
        "status": "SUCCESS",
        "input_file": "/confidential/raw/findings.csv",
        "input_rows": 1,
        "output_findings": 1,
        "findings_artifact": "PARSER-Findings-20260908-120000.json",
        "errors": 0,
        "warnings": 0,
        "infos": 0,
        "retry_count": 0,
        "max_attempts": 3,
        "application_enrichment_status": "SKIPPED_NO_SOURCE",
        "anomalies_artifact": "parser_anomalies.json",
        "analysis_report_artifact": "PARSER-Finding_Analysis-20260908-120000.json",
        "open_points": [],
        "kri_ras9": {},
        "duration_seconds": 0.1,
    }
    payload.update(overrides)
    return ParserResult.model_validate(payload)


def parser_anomaly(severity: str, row_index: int) -> Anomaly:
    classifications = {
        "INFO": "INFO",
        "WARNING": "WARNING",
        "ERROR": "ERROR_NON_REMEDIABLE",
    }
    return Anomaly.model_validate({
        "row_index": row_index,
        "rem_key_id": f"REM-{row_index}",
        "field": "source_field",
        "value": {"row": row_index},
        "severity": severity,
        "error_type": f"{severity}_CONTROL",
        "message": f"{severity} parser anomaly",
        "classification": classifications[severity],
    })


def mapped_finding() -> dict:
    return {
        "server": None,
        "vulnerability": None,
        "finding": {
            "application_auid": None,
            "source_payload": {},
        },
    }


class RecordingCursor:
    def __init__(self, connection):
        self.connection = connection
        self.current_result = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params):
        self.connection.calls.append((sql, params))
        self.current_result = None
        if sql.startswith("SELECT agent_id"):
            return
        if "RETURNING pipeline_run_id" in sql:
            self.current_result = (params[0],)
        elif "RETURNING agent_id" in sql:
            self.current_result = (self.connection.agent_id,)
        elif "RETURNING agent_run_id" in sql:
            self.current_result = (self.connection.agent_run_id,)
        elif "RETURNING finding_id" in sql:
            self.connection.finding_id += 1
            self.current_result = (self.connection.finding_id,)
        elif "RETURNING anomaly_id" in sql:
            self.connection.anomaly_id += 1
            self.current_result = (self.connection.anomaly_id,)
        elif "RETURNING artifact_id" in sql:
            self.connection.artifact_id += 1
            self.current_result = (self.connection.artifact_id,)

    def fetchone(self):
        return self.current_result


class RecordingConnection:
    def __init__(self):
        self.calls = []
        self.agent_id = 41
        self.agent_run_id = 42
        self.finding_id = 100
        self.anomaly_id = 200
        self.artifact_id = 300
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return RecordingCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def find_call(connection, prefix):
    return next((sql, params) for sql, params in connection.calls if sql.startswith(prefix))


@pytest.mark.parametrize("parser_status", PARSER_FINAL_STATUSES)
def test_loader_preserves_each_parser_status_in_run_and_agent_rows(
    tmp_path, parser_status,
):
    applications_source = tmp_path / "obj_applications.jsonl"
    applications_source.write_text("", encoding="utf-8")
    findings_source = tmp_path / "obj_findings_enriched.jsonl"
    findings_source.write_text("", encoding="utf-8")
    result = parser_result(
        status=parser_status,
        input_rows=0,
        output_findings=0,
    )
    connection = RecordingConnection()
    run_id = UUID("00000000-0000-0000-0000-000000000123")

    loaded_run_id = load_transaction(
        connection,
        [],
        [],
        applications_source,
        findings_source,
        run_id=run_id,
        parser_result=result,
        parser_anomalies=[],
        artifacts=[],
    )

    assert loaded_run_id == run_id
    _, pipeline_insert = find_call(connection, "INSERT INTO pipeline_run")
    _, agent_run_insert = find_call(connection, "INSERT INTO agent_run")
    _, agent_finish = find_call(connection, "UPDATE agent_run")
    _, pipeline_finish = find_call(connection, "UPDATE pipeline_run")
    assert pipeline_insert[3] == parser_status
    assert agent_run_insert[5] == parser_status
    assert agent_finish[1] == parser_status
    assert pipeline_finish[1] == parser_status
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_loader_uses_parser_counts_and_persists_every_anomaly_as_run_level(
    tmp_path,
):
    applications_source = tmp_path / "obj_applications.jsonl"
    applications_source.write_text("", encoding="utf-8")
    findings_source = tmp_path / "obj_findings_enriched.jsonl"
    findings_source.write_text("{}\n", encoding="utf-8")
    anomalies = [
        parser_anomaly("INFO", 1),
        parser_anomaly("WARNING", 2),
        parser_anomaly("ERROR", 3),
    ]
    result = parser_result(
        status="FAILED_AFTER_RETRIES",
        input_file="C:/secure/source/RAW Finding.csv",
        input_rows=19,
        output_findings=1,
        infos=1,
        warnings=1,
        errors=1,
        retry_count=3,
    )
    connection = RecordingConnection()
    run_id = UUID("00000000-0000-0000-0000-000000000456")

    load_transaction(
        connection,
        [],
        [mapped_finding()],
        applications_source,
        findings_source,
        run_id=run_id,
        parser_result=result,
        parser_anomalies=anomalies,
        artifacts=[],
    )

    _, pipeline_insert = find_call(connection, "INSERT INTO pipeline_run")
    assert pipeline_insert[0] == run_id
    assert pipeline_insert[3] == "FAILED_AFTER_RETRIES"
    assert pipeline_insert[4] == "C:/secure/source/RAW Finding.csv"
    assert pipeline_insert[5:9] == (19, 1, 1, 1)

    _, agent_run_insert = find_call(connection, "INSERT INTO agent_run")
    assert agent_run_insert[0] == run_id
    assert agent_run_insert[1] == connection.agent_id
    assert agent_run_insert[5] == "FAILED_AFTER_RETRIES"

    anomaly_calls = [
        params
        for sql, params in connection.calls
        if sql.startswith("INSERT INTO anomaly")
    ]
    assert len(anomaly_calls) == 3
    assert [params[3] for params in anomaly_calls] == ["INFO", "WARNING", "ERROR"]
    assert all(params[0] == run_id for params in anomaly_calls)
    assert all(params[1] == connection.agent_run_id for params in anomaly_calls)
    assert all(params[2] is None for params in anomaly_calls)
    assert json.loads(anomaly_calls[0][6]) == {
        "row_index": 1,
        "rem_key_id": "REM-1",
        "field": "source_field",
        "value": {"row": 1},
        "classification": "INFO",
    }

    _, pipeline_finish = find_call(connection, "UPDATE pipeline_run")
    assert pipeline_finish[1] == "FAILED_AFTER_RETRIES"
    assert pipeline_finish[2] == 1


@pytest.mark.parametrize(
    ("result_overrides", "anomalies", "message"),
    [
        ({"output_findings": 2}, [], "output_findings"),
        (
            {"status": "SUCCESS_WITH_WARNINGS", "warnings": 1},
            [],
            "anomaly counters",
        ),
    ],
)
def test_cli_rejects_parser_artifact_count_mismatches_before_loading(
    tmp_path, capsys, result_overrides, anomalies, message,
):
    applications_path = tmp_path / "obj_applications.jsonl"
    applications_path.write_text("", encoding="utf-8")
    findings_path = tmp_path / "obj_findings_enriched.jsonl"
    findings_path.write_text("{}\n", encoding="utf-8")
    anomalies_path = tmp_path / "parser_anomalies.json"
    anomalies_path.write_text(
        json.dumps([item.model_dump(mode="json") for item in anomalies]),
        encoding="utf-8",
    )
    result_path = tmp_path / "PARSER-Result.json"
    result_path.write_text(
        parser_result(**result_overrides).model_dump_json(),
        encoding="utf-8",
    )

    exit_code = main([
        "--applications", str(applications_path),
        "--findings", str(findings_path),
        "--parser-result", str(result_path),
        "--parser-anomalies", str(anomalies_path),
        "--dry-run",
    ])

    assert exit_code == 2
    assert message in capsys.readouterr().err


def test_parser_result_and_anomalies_cli_arguments_are_required(tmp_path):
    applications_path = tmp_path / "obj_applications.jsonl"
    applications_path.write_text("", encoding="utf-8")
    findings_path = tmp_path / "obj_findings_enriched.jsonl"
    findings_path.write_text("", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main([
            "--applications", str(applications_path),
            "--findings", str(findings_path),
            "--dry-run",
        ])

    assert exc_info.value.code == 2
