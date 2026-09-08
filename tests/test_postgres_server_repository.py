from pathlib import Path

import pytest

from src.persistence.postgres_repository import (
    SERVER_COLUMNS,
    SERVER_SOURCE_APM,
    SERVER_SOURCE_FINDING,
    PostgresFindingRepository,
    normalize_hostname,
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
        if sql.startswith("SELECT server_id,"):
            self.current_result = self.connection.server_result
        elif "RETURNING server_id" in sql:
            self.current_result = (self.connection.inserted_server_id,)
        else:
            self.current_result = None

    def fetchone(self):
        return self.current_result


class FakeConnection:
    def __init__(self, server_result=None, inserted_server_id=1):
        self.calls = []
        self.server_result = server_result
        self.inserted_server_id = inserted_server_id

    def cursor(self):
        return FakeCursor(self)


def existing_server_result(server_id=42, **overrides):
    values = {column: None for column in SERVER_COLUMNS}
    values["hostname"] = "server01"
    values.update(overrides)
    return (server_id, *(values[column] for column in SERVER_COLUMNS))


@pytest.mark.parametrize("value", [None, "", "   ", "null", " N/A ", 123])
def test_invalid_hostname_does_not_create_server(value):
    connection = FakeConnection()

    server_id = PostgresFindingRepository(connection).upsert_server(
        {"hostname": value}, source=SERVER_SOURCE_APM,
    )

    assert server_id is None
    assert connection.calls == []


def test_hostname_is_trimmed_without_changing_case():
    assert normalize_hostname("  Server-01  ") == "Server-01"

    connection = FakeConnection(inserted_server_id=7)
    server_id = PostgresFindingRepository(connection).upsert_server(
        {"hostname": "  Server-01  ", "operating_system": "Linux"},
        source=SERVER_SOURCE_APM,
    )

    assert server_id == 7
    assert connection.calls[0][1] == ("Server-01",)
    inserted = dict(zip(SERVER_COLUMNS, connection.calls[1][1]))
    assert inserted["hostname"] == "Server-01"
    assert "ON CONFLICT (hostname) DO NOTHING" in connection.calls[1][0]


def test_apm_insert_keeps_only_official_os_fields():
    connection = FakeConnection()
    repository = PostgresFindingRepository(connection)

    repository.upsert_server({
        "hostname": "server01",
        "operating_system": "Red Hat 9.4",
        "os_name": "Red Hat",
        "os_version": "9.4",
        "environment": "PROD",
        "environment_detail": "Production",
        "sensitive": True,
        "authenticated_scan": True,
    }, source=SERVER_SOURCE_APM)

    inserted = dict(zip(SERVER_COLUMNS, connection.calls[1][1]))
    assert inserted == {
        "hostname": "server01",
        "operating_system": "Red Hat 9.4",
        "os_name": "Red Hat",
        "os_version": "9.4",
        "environment": None,
        "environment_detail": None,
        "sensitive": None,
        "authenticated_scan": None,
    }


def test_apm_completes_null_os_and_updates_timestamp():
    connection = FakeConnection(server_result=existing_server_result())
    repository = PostgresFindingRepository(connection)

    server_id = repository.upsert_server({
        "hostname": "server01", "operating_system": "Linux",
    }, source=SERVER_SOURCE_APM)

    assert server_id == 42
    assert connection.calls[1] == (
        "UPDATE server SET operating_system = %s, updated_at = CURRENT_TIMESTAMP "
        "WHERE server_id = %s",
        ("Linux", 42),
    )


def test_apm_replaces_different_os_without_overwriting_environment():
    connection = FakeConnection(server_result=existing_server_result(
        operating_system="Old Linux",
        os_name="Old",
        os_version="1",
        environment="PRODUCTION",
    ))
    repository = PostgresFindingRepository(connection)

    repository.upsert_server({
        "hostname": "server01",
        "operating_system": "Red Hat 9.4",
        "os_name": "Red Hat",
        "os_version": "9.4",
        "environment": "PROD",
    }, source=SERVER_SOURCE_APM)

    sql, params = connection.calls[1]
    assert sql == (
        "UPDATE server SET operating_system = %s, os_name = %s, os_version = %s, "
        "updated_at = CURRENT_TIMESTAMP WHERE server_id = %s"
    )
    assert "environment" not in sql
    assert params == ("Red Hat 9.4", "Red Hat", "9.4", 42)


def test_identical_or_null_apm_os_does_not_run_update():
    connection = FakeConnection(server_result=existing_server_result(
        operating_system="Linux", os_name="Linux", os_version="9",
    ))
    repository = PostgresFindingRepository(connection)

    repository.upsert_server({
        "hostname": "server01",
        "operating_system": "Linux",
        "os_name": "Linux",
        "os_version": None,
    }, source=SERVER_SOURCE_APM)

    assert len(connection.calls) == 1
    assert "updated_at" not in connection.calls[0][0]


def test_finding_updates_its_fields_and_uses_os_only_as_null_fallback():
    connection = FakeConnection(server_result=existing_server_result(
        operating_system="APM Linux",
        os_name=None,
        os_version="9",
        environment="NON-PRODUCTION",
        environment_detail="Development",
        sensitive=False,
        authenticated_scan=True,
    ))
    repository = PostgresFindingRepository(connection)

    repository.upsert_server({
        "hostname": "server01",
        "operating_system": "Finding Linux",
        "os_name": "Linux",
        "os_version": "10",
        "environment": "PRODUCTION",
        "environment_detail": "Production",
        "sensitive": True,
        "authenticated_scan": False,
    }, source=SERVER_SOURCE_FINDING)

    sql, params = connection.calls[1]
    assert "operating_system = %s" not in sql
    assert "os_name = %s" in sql
    assert "os_version = %s" not in sql
    assert "environment = %s" in sql
    assert "environment_detail = %s" in sql
    assert "sensitive = %s" in sql
    assert "authenticated_scan = %s" in sql
    assert params == ("Linux", "PRODUCTION", "Production", True, False, 42)


def test_application_server_relation_insert_is_idempotent():
    connection = FakeConnection()
    repository = PostgresFindingRepository(connection)

    repository.upsert_application_server_relation(10, 20)

    assert connection.calls == [(
        "INSERT INTO application_server_relation (application_id, server_id) "
        "VALUES (%s, %s) ON CONFLICT (application_id, server_id) DO NOTHING",
        (10, 20),
    )]


def test_null_application_server_relation_is_not_inserted():
    connection = FakeConnection()
    repository = PostgresFindingRepository(connection)

    repository.upsert_application_server_relation(None, 20)
    repository.upsert_application_server_relation(10, None)

    assert connection.calls == []


def test_server_ddl_defines_canonical_hostname_and_application_relation():
    ddl = Path("database/001_create_tables.sql").read_text(encoding="utf-8")
    server_table = ddl.split("CREATE TABLE server (", 1)[1].split(");", 1)[0]
    relation_table = ddl.split(
        "CREATE TABLE application_server_relation (", 1
    )[1].split(");", 1)[0]

    assert "hostname TEXT NOT NULL" in server_table
    assert "CHECK (hostname = BTRIM(hostname) AND hostname <> '')" in server_table
    assert "CONSTRAINT uq_server_hostname UNIQUE (hostname)" in server_table
    assert "application_id BIGINT NOT NULL REFERENCES application(application_id)" in relation_table
    assert "server_id BIGINT NOT NULL REFERENCES server(server_id)" in relation_table
    assert "PRIMARY KEY (application_id, server_id)" in relation_table


def test_server_migration_deletes_only_unreferenced_invalid_rows():
    migration = Path("database/003_server_dimension.sql").read_text(encoding="utf-8")

    assert "CREATE TABLE IF NOT EXISTS application_server_relation" in migration
    assert "DELETE FROM server AS s" in migration
    assert "WHERE f.server_id = s.server_id" in migration
    assert "WHERE relation.server_id = s.server_id" in migration
    assert "RETURNING s.server_id, s.hostname, s.created_at, s.updated_at" in migration


def test_server_migration_diagnoses_and_blocks_referenced_invalid_rows():
    migration = Path("database/003_server_dimension.sql").read_text(encoding="utf-8")

    assert "s.server_id" in migration
    assert "s.hostname" in migration
    assert "COUNT(DISTINCT f.finding_id) AS linked_findings" in migration
    assert "s.created_at" in migration
    assert "s.updated_at" in migration
    assert "SERVER_MIGRATION_INVALID_HOSTNAME_REFERENCED" in migration
    assert "linked_application_relations" in migration
    assert "Assign a verified hostname or explicitly detach" in migration


def test_server_migration_diagnoses_trimmed_duplicates_before_uniqueness():
    migration = Path("database/003_server_dimension.sql").read_text(encoding="utf-8")

    assert "BTRIM(hostname) AS normalized_hostname" in migration
    assert "HAVING COUNT(*) > 1" in migration
    assert "SERVER_MIGRATION_DUPLICATE_HOSTNAME" in migration
    assert "server_ids=[%s]" in migration
    assert "CREATE UNIQUE INDEX IF NOT EXISTS uq_server_hostname" in migration
