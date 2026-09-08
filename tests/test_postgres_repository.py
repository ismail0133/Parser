import json
import warnings

import pytest

from scripts.load_obj_findings_to_postgres import (
    load_transaction,
    prepare_inputs,
    prepare_server_inputs,
)
from src.models.application import ObjApplication
from src.models.parser_result import ParserResult
from src.models.server import ObjServer
from src.persistence.postgres_repository import (
    APPLICATION_APM_COLUMNS,
    APPLICATION_COLUMNS,
    SERVER_COLUMNS,
    PostgresFindingRepository,
)


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.current_result = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params):
        self.connection.calls.append((sql, params))
        if self.connection.fail_on and self.connection.fail_on in sql:
            raise RuntimeError("database failure")
        if "WITH servers_by_hostname" in sql:
            self.current_result = self.connection.kri_result
        elif sql.startswith("SELECT application_id,"):
            self.current_result = self.connection.application_result
        elif sql.startswith("SELECT"):
            self.current_result = None
        elif "RETURNING" in sql:
            self.connection.sequence += 1
            self.current_result = (self.connection.sequence,)

    def fetchone(self):
        return self.current_result


class FakeConnection:
    def __init__(self, fail_on=None, kri_result=None, application_result=None):
        self.calls = []
        self.sequence = 0
        self.fail_on = fail_on
        self.kri_result = kri_result
        self.application_result = application_result
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def parser_result(output_findings):
    return ParserResult(
        status="SUCCESS",
        input_file="source.csv",
        input_rows=output_findings,
        output_findings=output_findings,
        findings_artifact="obj_findings.jsonl",
        errors=0,
        warnings=0,
        infos=0,
        retry_count=0,
        max_attempts=3,
        application_enrichment_status="SKIPPED_NO_SOURCE",
        anomalies_artifact="parser_anomalies.json",
        analysis_report_artifact="parser_analysis.json",
        open_points=[],
        kri_ras9={},
        duration_seconds=0.1,
    )


def test_repository_uses_placeholders_and_separate_parameters():
    connection = FakeConnection()
    repository = PostgresFindingRepository(connection)
    dangerous = "x'); DROP TABLE finding; --"
    repository.create_server({"hostname": dangerous})
    sql, params = connection.calls[0]
    assert dangerous not in sql
    assert "%s" in sql
    assert params[0] == dangerous


def test_application_is_looked_up_by_confirmed_auid():
    connection = FakeConnection()
    repository = PostgresFindingRepository(connection)
    repository.get_or_create_application({"auid": "AP10426", "application_name": "App"})
    select_sql, select_params = connection.calls[0]
    insert_sql, insert_params = connection.calls[1]
    assert select_sql.startswith("SELECT application_id, auid, code_app")
    assert select_sql.endswith("FROM application WHERE auid = %s FOR UPDATE")
    assert select_params == ("AP10426",)
    assert "AP10426" not in insert_sql
    assert insert_params[0] == "AP10426"


def existing_application_result(application_id=42, **overrides):
    values = {column: None for column in APPLICATION_COLUMNS}
    values["auid"] = "AP10426"
    values.update(overrides)
    return (application_id, *(values[column] for column in APPLICATION_COLUMNS))


def test_existing_application_null_columns_are_completed():
    connection = FakeConnection(application_result=existing_application_result())
    repository = PostgresFindingRepository(connection)

    application_id = repository.get_or_create_application({
        "auid": "AP10426",
        "application_name": "App",
        "vital": "GROUPE",
        "continuity_level": "HIGH",
        "application_manager": "Application Manager",
        "domain_manager": "Domain Manager",
    })

    assert application_id == 42
    update_sql, update_params = connection.calls[1]
    assert update_sql.startswith("UPDATE application SET application_name = %s")
    assert "vital = %s" in update_sql
    assert "continuity_level = %s" in update_sql
    assert "application_manager = %s" in update_sql
    assert "domain_manager = %s" in update_sql
    assert update_sql.endswith(
        "updated_at = CURRENT_TIMESTAMP WHERE application_id = %s"
    )
    assert update_params == (
        "App", "GROUPE", "HIGH", "Application Manager", "Domain Manager", 42,
    )


def test_apm_replaces_existing_different_value_without_to_validate_warning():
    connection = FakeConnection(application_result=existing_application_result(
        application_name="Existing App",
    ))
    repository = PostgresFindingRepository(connection)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        application_id = repository.get_or_create_application({
            "auid": "AP10426", "application_name": "Official APM App",
        })

    assert application_id == 42
    update_sql, update_params = connection.calls[1]
    assert update_sql == (
        "UPDATE application SET application_name = %s, updated_at = CURRENT_TIMESTAMP "
        "WHERE application_id = %s"
    )
    assert update_params == ("Official APM App", 42)
    assert caught == []


@pytest.mark.parametrize("column", APPLICATION_APM_COLUMNS)
def test_each_official_apm_column_replaces_an_existing_different_value(column):
    connection = FakeConnection(application_result=existing_application_result(**{
        column: "Old value",
    }))
    repository = PostgresFindingRepository(connection)

    repository.get_or_create_application({"auid": "AP10426", column: "Official APM value"})

    update_sql, update_params = connection.calls[1]
    assert update_sql == (
        f"UPDATE application SET {column} = %s, updated_at = CURRENT_TIMESTAMP "
        "WHERE application_id = %s"
    )
    assert update_params == ("Official APM value", 42)


def test_identical_apm_value_does_not_update_application_or_updated_at():
    connection = FakeConnection(application_result=existing_application_result(
        application_name="Official APM App",
    ))
    repository = PostgresFindingRepository(connection)

    application_id = repository.get_or_create_application({
        "auid": "AP10426", "application_name": "Official APM App",
    })

    assert application_id == 42
    assert len(connection.calls) == 1
    assert all("updated_at" not in sql for sql, _ in connection.calls)


def test_missing_apm_value_does_not_update_application_or_updated_at():
    connection = FakeConnection(application_result=existing_application_result(
        application_name="Existing App",
    ))
    repository = PostgresFindingRepository(connection)

    application_id = repository.get_or_create_application({
        "auid": "AP10426", "application_name": None,
    })

    assert application_id == 42
    assert len(connection.calls) == 1
    assert all("updated_at" not in sql for sql, _ in connection.calls)


def test_only_confirmed_apm_columns_are_authoritative_on_update():
    assert APPLICATION_APM_COLUMNS == (
        "trigram", "application_name", "appsec", "business_line", "vital",
        "continuity_level", "application_manager", "domain_manager",
        "production_domain_manager", "production_manager",
    )

    connection = FakeConnection(application_result=existing_application_result(
        code_app="Existing non-APM code", trigram="OLD",
    ))
    repository = PostgresFindingRepository(connection)

    repository.get_or_create_application({
        "auid": "AP10426", "code_app": "Incoming code", "trigram": "APM",
    })

    update_sql, update_params = connection.calls[1]
    assert "code_app" not in update_sql
    assert update_params == ("APM", 42)


def test_real_obj_application_jsonl_reaches_repository_insert(tmp_path):
    application = ObjApplication(
        auid="AP10426",
        trigram="ABC",
        name="App",
        business_line="Retail",
        appsec="P4",
        vital="GROUPE",
        continuity_level="HIGH",
        application_manager="Application Manager",
        domain_manager="Domain Manager",
        production_manager="Production Manager",
        production_domain_manager="Production Domain Manager",
    )
    applications_source = tmp_path / "obj_applications.jsonl"
    applications_source.write_text(application.model_dump_json() + "\n", encoding="utf-8")
    findings_source = tmp_path / "obj_findings_enriched.jsonl"
    findings_source.write_text("", encoding="utf-8")
    applications, findings, stats, _ = prepare_inputs(applications_source, findings_source)
    connection = FakeConnection()

    load_transaction(
        connection, applications, findings, applications_source, findings_source,
        parser_result=parser_result(0), parser_anomalies=[], artifacts=[],
    )

    assert stats.status == "READY"
    insert_params = next(
        params for sql, params in connection.calls if sql.startswith("INSERT INTO application")
    )
    inserted_application = dict(zip(APPLICATION_COLUMNS, insert_params))
    assert inserted_application == {
        "auid": "AP10426",
        "code_app": None,
        "trigram": "ABC",
        "application_name": "App",
        "appsec": "P4",
        "business_line": "Retail",
        "vital": "GROUPE",
        "continuity_level": "HIGH",
        "application_manager": "Application Manager",
        "domain_manager": "Domain Manager",
        "production_domain_manager": "Production Domain Manager",
        "production_manager": "Production Manager",
    }


def test_real_obj_server_jsonl_reaches_repository_and_relation_insert(tmp_path):
    applications_source = tmp_path / "obj_applications.jsonl"
    applications_source.write_text("{}\n", encoding="utf-8")
    findings_source = tmp_path / "obj_findings_enriched.jsonl"
    findings_source.write_text("", encoding="utf-8")
    servers_source = tmp_path / "obj_servers.jsonl"
    servers_source.write_text(ObjServer(
        hostname=" server01 ",
        operating_system="Red Hat Enterprise Linux 9.6",
        os_name="Red Hat Enterprise Linux",
        os_version="9.6",
        environment="PROD",
    ).model_dump_json() + "\n", encoding="utf-8")
    relations_source = tmp_path / "application_server_relations.jsonl"
    relations_source.write_text(
        json.dumps({"auid": "AP10426", "hostname": "server01"}) + "\n",
        encoding="utf-8",
    )
    servers, relations, stats, messages = prepare_server_inputs(
        servers_source,
        relations_source,
        application_auids={"AP10426"},
    )
    connection = FakeConnection()

    load_transaction(
        connection,
        [{"auid": "AP10426", "application_name": "App"}],
        [],
        applications_source,
        findings_source,
        parser_result=parser_result(0),
        parser_anomalies=[],
        artifacts=[],
        servers=servers,
        server_relations=relations,
    )

    inserted_params = next(
        params for sql, params in connection.calls if sql.startswith("INSERT INTO server")
    )
    inserted_server = dict(zip(SERVER_COLUMNS, inserted_params))
    assert inserted_server == {
        "hostname": "server01",
        "operating_system": "Red Hat Enterprise Linux 9.6",
        "os_name": "Red Hat Enterprise Linux",
        "os_version": "9.6",
        # Raw APM environment is intentionally not persisted as the normalized category.
        "environment": None,
        "environment_detail": None,
        "sensitive": None,
        "authenticated_scan": None,
    }
    relation_params = next(
        params
        for sql, params in connection.calls
        if sql.startswith("INSERT INTO application_server_relation")
    )
    assert relation_params[0] is not None
    assert relation_params[1] is not None
    assert stats.apm_servers_mapped == 1
    assert messages == []


def test_kri_control_is_scoped_and_returns_json_compatible_values():
    connection = FakeConnection(kri_result=(57, 100, 57))
    repository = PostgresFindingRepository(connection)

    result = repository.calculate_kri_ras9("run-123")

    sql, params = connection.calls[0]
    assert "f.pipeline_run_id = %s" in sql
    assert "run-123" not in sql
    assert params == ("run-123",)
    assert result == {
        "pipeline_run_id": "run-123",
        "numerator": 57,
        "denominator": 100,
        "kri_percentage": 57.0,
    }


def test_kri_control_returns_none_when_denominator_is_zero():
    connection = FakeConnection(kri_result=(0, 0, None))
    result = PostgresFindingRepository(connection).calculate_kri_ras9("run-empty")
    assert result["kri_percentage"] is None


def mapped_finding(auid=None):
    return {
        "server": {"hostname": "host", "operating_system": None, "os_name": None,
                   "os_version": None, "environment": None, "environment_detail": None,
                   "sensitive": False, "authenticated_scan": True},
        "vulnerability": {"cve_code": "CVE-1", "title": None, "description": None,
                          "severity_level": None, "cvss_score": None},
        "finding": {"application_auid": auid, "source_payload": {"cve": "CVE-1"}},
    }


def test_transaction_orders_run_before_dimensions_and_commits(tmp_path):
    source = tmp_path / "obj_findings.jsonl"
    source.write_text(json.dumps({"cve": "CVE-1"}) + "\n", encoding="utf-8")
    applications_source = tmp_path / "obj_applications.jsonl"
    applications_source.write_text("", encoding="utf-8")
    connection = FakeConnection()
    load_transaction(
        connection, [], [mapped_finding()], applications_source, source,
        parser_result=parser_result(1), parser_anomalies=[], artifacts=[],
    )
    statements = [sql for sql, _ in connection.calls]
    assert statements[0].startswith("INSERT INTO pipeline_run")
    assert next(i for i, sql in enumerate(statements) if "INSERT INTO server" in sql) > 0
    assert next(i for i, sql in enumerate(statements) if "INSERT INTO finding" in sql) > next(
        i for i, sql in enumerate(statements) if "INSERT INTO server" in sql
    )
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_transaction_rolls_back_on_error(tmp_path):
    source = tmp_path / "obj_findings.jsonl"
    source.write_text("{}\n", encoding="utf-8")
    applications_source = tmp_path / "obj_applications.jsonl"
    applications_source.write_text("", encoding="utf-8")
    connection = FakeConnection(fail_on="INSERT INTO finding")
    with pytest.raises(RuntimeError, match="database failure"):
        load_transaction(
            connection, [], [mapped_finding()], applications_source, source,
            parser_result=parser_result(1), parser_anomalies=[], artifacts=[],
        )
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_transaction_resolves_one_application_for_many_findings(tmp_path):
    findings_source = tmp_path / "obj_findings_enriched.jsonl"
    findings_source.write_text("{}\n{}\n", encoding="utf-8")
    applications_source = tmp_path / "obj_applications.jsonl"
    applications_source.write_text("{}\n", encoding="utf-8")
    connection = FakeConnection()
    application = {"auid": "AP1", "application_name": "App"}
    load_transaction(connection, [application], [mapped_finding("AP1"), mapped_finding("AP1")],
                     applications_source, findings_source,
                     parser_result=parser_result(2), parser_anomalies=[], artifacts=[])
    statements = [sql for sql, _ in connection.calls]
    assert sum("INSERT INTO application" in sql for sql in statements) == 1
    finding_params = [params for sql, params in connection.calls if "INSERT INTO finding" in sql]
    assert len(finding_params) == 2
    assert all(params[1] is not None for params in finding_params)


def test_transaction_accepts_null_application_id(tmp_path):
    findings_source = tmp_path / "obj_findings_enriched.jsonl"
    findings_source.write_text("{}\n", encoding="utf-8")
    applications_source = tmp_path / "obj_applications.jsonl"
    applications_source.write_text("", encoding="utf-8")
    connection = FakeConnection()
    load_transaction(
        connection, [], [mapped_finding()], applications_source, findings_source,
        parser_result=parser_result(1), parser_anomalies=[], artifacts=[],
    )
    params = next(params for sql, params in connection.calls if "INSERT INTO finding" in sql)
    assert params[1] is None


def test_transaction_persists_unresolved_auid_anomaly(tmp_path):
    findings_source = tmp_path / "obj_findings_enriched.jsonl"
    findings_source.write_text("{}\n", encoding="utf-8")
    applications_source = tmp_path / "obj_applications.jsonl"
    applications_source.write_text("", encoding="utf-8")
    connection = FakeConnection()
    load_transaction(
        connection, [], [mapped_finding("AP999")], applications_source, findings_source,
        parser_result=parser_result(1), parser_anomalies=[], artifacts=[],
    )
    anomaly_params = next(params for sql, params in connection.calls if "INSERT INTO anomaly" in sql)
    assert anomaly_params[4] == "UNRESOLVED_APPLICATION_AUID"
    assert json.loads(anomaly_params[6]) == {"auid": "AP999"}
