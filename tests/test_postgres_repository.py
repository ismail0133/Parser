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


def mapped_finding():
    return {
        "application": None,
        "server": {"hostname": "host", "operating_system": None, "os_name": None,
                   "os_version": None, "environment": None, "environment_detail": None,
                   "sensitive": False, "authenticated_scan": True},
        "vulnerability": {"cve_code": "CVE-1", "title": None, "description": None,
                          "severity_level": None, "cvss_score": None},
        "finding": {"source_payload": {"cve": "CVE-1"}},
    }


def test_transaction_orders_run_before_dimensions_and_commits(tmp_path):
    source = tmp_path / "obj_findings.jsonl"
    source.write_text(json.dumps({"cve": "CVE-1"}) + "\n", encoding="utf-8")
    connection = FakeConnection()
    load_transaction(connection, [mapped_finding()], source)
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
    connection = FakeConnection(fail_on="INSERT INTO finding")
    with pytest.raises(RuntimeError, match="database failure"):
        load_transaction(connection, [mapped_finding()], source)
    assert connection.commits == 0
    assert connection.rollbacks == 1
