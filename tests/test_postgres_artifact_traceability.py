import hashlib
import json
from pathlib import Path
from uuid import UUID

import pytest

from scripts.load_obj_findings_to_postgres import (
    load_transaction,
    prepare_artifact_inputs,
)
from src.models.parser_result import ParserResult
from src.persistence.artifact_mapper import (
    APPLICATION_SERVER_RELATIONS_JSONL,
    OBJ_APPLICATIONS_JSONL,
    OBJ_FINDINGS_ENRICHED_JSONL,
    OBJ_FINDINGS_JSONL,
    OBJ_SERVERS_JSONL,
    PARSER_ANOMALIES_JSON,
    PARSER_RESULT_JSON,
    prepare_artifact,
)
from src.persistence.postgres_repository import (
    ARTIFACT_COLUMNS,
    ArtifactHashConflictError,
    PostgresFindingRepository,
)


RUN_ID = UUID("00000000-0000-0000-0000-000000000789")


def parser_result(**overrides) -> ParserResult:
    payload = {
        "status": "SUCCESS",
        "input_file": "raw.csv",
        "input_rows": 0,
        "output_findings": 0,
        "findings_artifact": "PARSER-Findings.json",
        "errors": 0,
        "warnings": 0,
        "infos": 0,
        "retry_count": 0,
        "max_attempts": 3,
        "application_enrichment_status": "SKIPPED_NO_SOURCE",
        "anomalies_artifact": "parser_anomalies.json",
        "analysis_report_artifact": "PARSER-Finding_Analysis.json",
        "open_points": [],
        "kri_ras9": {},
        "duration_seconds": 0.1,
    }
    payload.update(overrides)
    return ParserResult.model_validate(payload)


def write_cli_artifacts(tmp_path: Path, *, parser_findings: bool = False):
    applications = tmp_path / "obj_applications.jsonl"
    findings = tmp_path / (
        "obj_findings.jsonl" if parser_findings else "obj_findings_enriched.jsonl"
    )
    anomalies = tmp_path / "parser_anomalies.json"
    servers = tmp_path / "obj_servers.jsonl"
    relations = tmp_path / "application_server_relations.jsonl"
    for path in (applications, findings, servers, relations):
        path.write_text("", encoding="utf-8")
    anomalies.write_text("[]", encoding="utf-8")
    result = parser_result(
        findings_artifact=findings.name if parser_findings else "PARSER-Findings.json"
    )
    result_path = tmp_path / "PARSER-Result.json"
    result_path.write_text(result.model_dump_json(), encoding="utf-8")
    return result, result_path, anomalies, applications, findings, servers, relations


class TraceCursor:
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
        if sql.startswith("SELECT artifact_id, sha256"):
            self.current_result = self.connection.artifacts.get(tuple(params))
            return
        if sql.startswith("INSERT INTO artifact"):
            if self.connection.fail_artifact_insert:
                raise RuntimeError("artifact insertion failure")
            row = dict(zip(ARTIFACT_COLUMNS, params))
            key = (
                row["pipeline_run_id"],
                row["artifact_type"],
                row["storage_path"],
            )
            if key in self.connection.artifacts:
                return
            self.connection.sequence += 1
            self.connection.artifacts[key] = (
                self.connection.sequence,
                row["sha256"],
            )
            self.current_result = (self.connection.sequence,)
            return
        if "RETURNING pipeline_run_id" in sql:
            self.current_result = (params[0],)
        elif "RETURNING agent_id" in sql:
            self.current_result = (41,)
        elif "RETURNING agent_run_id" in sql:
            self.current_result = (42,)
        elif "RETURNING" in sql:
            self.connection.sequence += 1
            self.current_result = (self.connection.sequence,)

    def fetchone(self):
        return self.current_result


class TraceConnection:
    def __init__(self, *, fail_artifact_insert=False):
        self.calls = []
        self.artifacts = {}
        self.sequence = 100
        self.fail_artifact_insert = fail_artifact_insert
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return TraceCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def artifact_insert_rows(connection):
    return [
        dict(zip(ARTIFACT_COLUMNS, params))
        for sql, params in connection.calls
        if sql.startswith("INSERT INTO artifact")
    ]


def test_main_schema_and_migration_define_artifact_traceability():
    ddl = Path("database/001_create_tables.sql").read_text(encoding="utf-8")
    migration = Path("database/004_artifact_traceability.sql").read_text(encoding="utf-8")
    artifact_table = ddl.split("CREATE TABLE artifact (", 1)[1].split(");", 1)[0]

    assert "pipeline_run_id UUID NOT NULL" in artifact_table
    assert "agent_run_id BIGINT" in artifact_table
    assert "row_count BIGINT" in artifact_table
    assert "REFERENCES pipeline_run(pipeline_run_id)" in artifact_table
    assert "REFERENCES agent_run(agent_run_id)" in artifact_table
    assert "FOREIGN KEY (pipeline_run_id, agent_run_id)" in artifact_table
    assert "CHECK (row_count >= 0)" in artifact_table
    assert "idx_artifact_pipeline_run_id" in migration
    assert "idx_artifact_agent_run_id" in migration
    assert "CHECK (pipeline_run_id IS NOT NULL) NOT VALID" in migration


def test_prepare_artifact_calculates_sha256_and_jsonl_row_count(tmp_path):
    source = tmp_path / "objects.jsonl"
    content = b'{"id": 1}\n\n  \n{"id": 2}\n'
    source.write_bytes(content)

    artifact = prepare_artifact(source, OBJ_APPLICATIONS_JSONL)

    assert artifact.sha256 == hashlib.sha256(content).hexdigest()
    assert artifact.row_count == 2


@pytest.mark.parametrize(
    ("filename", "payload", "expected_count"),
    [
        ("array.json", [{"id": 1}, {"id": 2}], 2),
        ("object.json", {"status": "SUCCESS"}, 1),
    ],
)
def test_prepare_artifact_counts_json_arrays_and_objects(
    tmp_path, filename, payload, expected_count,
):
    source = tmp_path / filename
    source.write_text(json.dumps(payload), encoding="utf-8")

    assert prepare_artifact(source, PARSER_RESULT_JSON).row_count == expected_count


def test_repository_insert_artifact_uses_all_parameters_and_is_idempotent(tmp_path):
    source = tmp_path / "parser_anomalies.json"
    source.write_text("[]", encoding="utf-8")
    prepared = prepare_artifact(source, PARSER_ANOMALIES_JSON, produced_by_parser=True)
    row = prepared.to_repository_row(pipeline_run_id=RUN_ID, parser_agent_run_id=42)
    connection = TraceConnection()
    repository = PostgresFindingRepository(connection)

    first_id = repository.insert_artifact(row)
    second_id = repository.insert_artifact(row)

    assert first_id == second_id
    inserts = [call for call in connection.calls if call[0].startswith("INSERT INTO artifact")]
    assert len(inserts) == 1
    assert dict(zip(ARTIFACT_COLUMNS, inserts[0][1])) == row


def test_repository_rejects_same_run_type_path_with_different_hash(tmp_path):
    source = tmp_path / "parser_anomalies.json"
    source.write_text("[]", encoding="utf-8")
    row = prepare_artifact(source, PARSER_ANOMALIES_JSON).to_repository_row(
        pipeline_run_id=RUN_ID,
        parser_agent_run_id=42,
    )
    connection = TraceConnection()
    repository = PostgresFindingRepository(connection)
    repository.insert_artifact(row)

    with pytest.raises(ArtifactHashConflictError, match="ARTIFACT_HASH_CONFLICT"):
        repository.insert_artifact({**row, "sha256": "f" * 64})


def test_loader_registers_every_cli_artifact_with_correct_lineage(tmp_path):
    result, result_path, anomalies, applications, findings, servers, relations = (
        write_cli_artifacts(tmp_path)
    )
    artifacts = prepare_artifact_inputs(
        applications,
        findings,
        result_path,
        anomalies,
        result,
        servers_source=servers,
        server_relations_source=relations,
    )
    connection = TraceConnection()

    load_transaction(
        connection,
        [],
        [],
        applications,
        findings,
        run_id=RUN_ID,
        parser_result=result,
        parser_anomalies=[],
        artifacts=artifacts,
    )

    rows = artifact_insert_rows(connection)
    assert {row["artifact_type"] for row in rows} == {
        PARSER_RESULT_JSON,
        PARSER_ANOMALIES_JSON,
        OBJ_APPLICATIONS_JSONL,
        OBJ_FINDINGS_ENRICHED_JSONL,
        OBJ_SERVERS_JSONL,
        APPLICATION_SERVER_RELATIONS_JSONL,
    }
    assert all(row["pipeline_run_id"] == RUN_ID for row in rows)
    parser_rows = {
        row["artifact_type"]: row
        for row in rows
        if row["artifact_type"] in {PARSER_RESULT_JSON, PARSER_ANOMALIES_JSON}
    }
    assert all(row["agent_run_id"] == 42 for row in parser_rows.values())
    non_parser_rows = [row for row in rows if row not in parser_rows.values()]
    assert all(row["agent_run_id"] is None for row in non_parser_rows)
    assert parser_rows[PARSER_RESULT_JSON]["row_count"] == 1
    assert parser_rows[PARSER_ANOMALIES_JSON]["row_count"] == 0
    paths_by_type = {
        PARSER_RESULT_JSON: result_path,
        PARSER_ANOMALIES_JSON: anomalies,
        OBJ_APPLICATIONS_JSONL: applications,
        OBJ_FINDINGS_ENRICHED_JSONL: findings,
        OBJ_SERVERS_JSONL: servers,
        APPLICATION_SERVER_RELATIONS_JSONL: relations,
    }
    assert all(
        row["sha256"] == hashlib.sha256(paths_by_type[row["artifact_type"]].read_bytes()).hexdigest()
        for row in rows
    )
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_parser_declared_findings_jsonl_receives_parser_agent_run(tmp_path):
    result, result_path, anomalies, applications, findings, _, _ = write_cli_artifacts(
        tmp_path,
        parser_findings=True,
    )

    rows = [
        artifact.to_repository_row(pipeline_run_id=RUN_ID, parser_agent_run_id=42)
        for artifact in prepare_artifact_inputs(
            applications,
            findings,
            result_path,
            anomalies,
            result,
        )
    ]
    finding_row = next(row for row in rows if row["artifact_type"] == OBJ_FINDINGS_JSONL)

    assert finding_row["agent_run_id"] == 42


def test_artifact_insert_failure_rolls_back_the_complete_load(tmp_path):
    result, result_path, anomalies, applications, findings, _, _ = write_cli_artifacts(tmp_path)
    artifacts = prepare_artifact_inputs(
        applications,
        findings,
        result_path,
        anomalies,
        result,
    )
    connection = TraceConnection(fail_artifact_insert=True)

    with pytest.raises(RuntimeError, match="artifact insertion failure"):
        load_transaction(
            connection,
            [],
            [],
            applications,
            findings,
            run_id=RUN_ID,
            parser_result=result,
            parser_anomalies=[],
            artifacts=artifacts,
        )

    assert connection.commits == 0
    assert connection.rollbacks == 1
