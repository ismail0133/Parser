import json

import pytest

from scripts.load_obj_findings_to_postgres import load_transaction
from src.persistence.postgres_repository import PostgresFindingRepository


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
        if sql.startswith("SELECT"):
            self.current_result = None
        elif "RETURNING" in sql:
            self.connection.sequence += 1
            self.current_result = (self.connection.sequence,)

    def fetchone(self):
        return self.current_result


class FakeConnection:
    def __init__(self, fail_on=None):
        self.calls = []
        self.sequence = 0
        self.fail_on = fail_on
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


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
    assert select_sql == "SELECT application_id FROM application WHERE auid = %s"
    assert select_params == ("AP10426",)
    assert "AP10426" not in insert_sql
    assert insert_params[0] == "AP10426"


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
    load_transaction(connection, [], [mapped_finding()], applications_source, source)
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
        load_transaction(connection, [], [mapped_finding()], applications_source, source)
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
                     applications_source, findings_source)
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
    load_transaction(connection, [], [mapped_finding()], applications_source, findings_source)
    params = next(params for sql, params in connection.calls if "INSERT INTO finding" in sql)
    assert params[1] is None


def test_transaction_persists_unresolved_auid_anomaly(tmp_path):
    findings_source = tmp_path / "obj_findings_enriched.jsonl"
    findings_source.write_text("{}\n", encoding="utf-8")
    applications_source = tmp_path / "obj_applications.jsonl"
    applications_source.write_text("", encoding="utf-8")
    connection = FakeConnection()
    load_transaction(connection, [], [mapped_finding("AP999")], applications_source, findings_source)
    anomaly_params = next(params for sql, params in connection.calls if "INSERT INTO anomaly" in sql)
    assert anomaly_params[4] == "UNRESOLVED_APPLICATION_AUID"
    assert json.loads(anomaly_params[6]) == {"auid": "AP999"}
