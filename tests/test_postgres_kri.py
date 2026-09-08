import sqlite3

import pytest

from src.persistence.postgres_repository import KRI_RAS9_SQL


class BoolOr:
    def __init__(self):
        self.seen = False
        self.value = False

    def step(self, value):
        if value is not None:
            self.seen = True
            self.value = self.value or bool(value)

    def finalize(self):
        return int(self.value) if self.seen else None


def calculate_sql_kri(rows, pipeline_run_id="run-1"):
    connection = sqlite3.connect(":memory:")
    connection.create_aggregate("BOOL_OR", 1, BoolOr)
    connection.create_function("BTRIM", 1, lambda value: value.strip())
    connection.executescript("""
        CREATE TABLE server (
            server_id INTEGER PRIMARY KEY,
            hostname TEXT,
            sensitive BOOLEAN,
            authenticated_scan BOOLEAN
        );
        CREATE TABLE finding (
            finding_id INTEGER PRIMARY KEY,
            pipeline_run_id TEXT,
            server_id INTEGER,
            severity_level TEXT,
            overdue BOOLEAN,
            false_positive BOOLEAN
        );
    """)
    servers = set()
    for finding_id, row in enumerate(rows, start=1):
        server_id = row.get("server_id", finding_id)
        if server_id not in servers:
            connection.execute(
                "INSERT INTO server VALUES (?, ?, ?, ?)",
                (
                    server_id,
                    row.get("hostname", "SERVER01"),
                    row.get("sensitive", True),
                    row.get("authenticated_scan", True),
                ),
            )
            servers.add(server_id)
        connection.execute(
            "INSERT INTO finding VALUES (?, ?, ?, ?, ?, ?)",
            (
                finding_id,
                row.get("pipeline_run_id", "run-1"),
                server_id,
                row.get("severity_level", "Medium"),
                row.get("overdue", False),
                row.get("false_positive", False),
            ),
        )
    sql = KRI_RAS9_SQL.replace("%s", "?")
    result = connection.execute(sql, (pipeline_run_id,)).fetchone()
    connection.close()
    return result


def test_eligible_hostname_with_qualifying_finding_is_in_both_counts():
    assert calculate_sql_kri([{
        "severity_level": "Critical", "overdue": True,
    }]) == (1, 1, 100.0)


def test_eligible_hostname_without_qualifying_finding_is_denominator_only():
    assert calculate_sql_kri([{"severity_level": "Medium"}]) == (0, 1, 0.0)


def test_multiple_qualifying_findings_count_hostname_once():
    rows = [
        {"hostname": "SERVER01", "severity_level": "Critical", "overdue": True},
        {"hostname": "SERVER01", "severity_level": "Very High", "overdue": True},
    ]
    assert calculate_sql_kri(rows) == (1, 1, 100.0)


def test_eligibility_and_qualifying_finding_can_be_on_different_rows():
    rows = [
        {"hostname": "SERVER01", "sensitive": True, "severity_level": "Medium"},
        {
            "hostname": "SERVER01", "sensitive": False,
            "severity_level": "Critical", "overdue": True,
        },
    ]
    assert calculate_sql_kri(rows) == (1, 1, 100.0)


@pytest.mark.parametrize(
    "server_values",
    [
        {"sensitive": False, "authenticated_scan": True},
        {"sensitive": True, "authenticated_scan": False},
    ],
)
def test_ineligible_hostname_is_excluded(server_values):
    row = {
        **server_values, "severity_level": "Critical", "overdue": True,
    }
    assert calculate_sql_kri([row]) == (0, 0, None)


def test_false_positive_is_not_qualifying():
    row = {
        "severity_level": "Critical", "overdue": True, "false_positive": True,
    }
    assert calculate_sql_kri([row]) == (0, 1, 0.0)


def test_null_false_positive_is_qualifying():
    row = {
        "severity_level": "Critical", "overdue": True, "false_positive": None,
    }
    assert calculate_sql_kri([row]) == (1, 1, 100.0)


@pytest.mark.parametrize(
    "severity", ["Critical", "critical", "CRITICAL", "Very High", "VERY HIGH"]
)
def test_severity_is_case_insensitive(severity):
    row = {"severity_level": severity, "overdue": True}
    assert calculate_sql_kri([row]) == (1, 1, 100.0)


@pytest.mark.parametrize("hostname", [None, "", "   "])
def test_missing_or_empty_hostname_is_excluded(hostname):
    row = {"hostname": hostname, "severity_level": "Critical", "overdue": True}
    assert calculate_sql_kri([row]) == (0, 0, None)


def test_pipeline_runs_are_never_mixed():
    rows = [
        {
            "pipeline_run_id": "run-1", "hostname": "SERVER01",
            "severity_level": "Critical", "overdue": True,
        },
        {
            "pipeline_run_id": "run-2", "hostname": "SERVER02",
            "severity_level": "Medium",
        },
    ]
    assert calculate_sql_kri(rows, "run-1") == (1, 1, 100.0)
    assert calculate_sql_kri(rows, "run-2") == (0, 1, 0.0)


def test_same_hostname_with_multiple_server_ids_counts_once():
    rows = [
        {
            "server_id": 10, "hostname": "SERVER01",
            "severity_level": "Critical", "overdue": True,
        },
        {"server_id": 20, "hostname": "SERVER01", "severity_level": "Medium"},
    ]
    assert calculate_sql_kri(rows) == (1, 1, 100.0)


def test_zero_denominator_does_not_divide_by_zero():
    assert calculate_sql_kri([]) == (0, 0, None)


def test_percentage_is_rounded_to_four_decimal_places():
    rows = [
        {"hostname": "SERVER01", "severity_level": "Critical", "overdue": True},
        {"hostname": "SERVER02", "severity_level": "Critical", "overdue": True},
        {"hostname": "SERVER03", "severity_level": "Medium"},
    ]
    assert calculate_sql_kri(rows) == (2, 3, 66.6667)
