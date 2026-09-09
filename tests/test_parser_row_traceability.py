import json

import pandas as pd
import pytest

from main import write_outputs
from src.cleaning.finding_cleaner import is_empty_source_row
from src.loaders.finding_loader import EXPECTED_COLUMNS
from src.parser import parse_findings
from tests.conftest import synthetic_row


def empty_source_row(value=""):
    return {column: value for column in EXPECTED_COLUMNS}


def test_empty_source_row_accepts_only_missing_or_blank_cells():
    assert is_empty_source_row(pd.Series([None, pd.NA, float("nan"), "", "   "]))
    assert not is_empty_source_row(pd.Series(["", "N/A"]))
    assert not is_empty_source_row(pd.Series(["", 0]))


@pytest.mark.parametrize("empty_value", ["", "   "])
def test_fully_empty_final_csv_row_is_ignored(csv_factory, empty_value):
    path = csv_factory([synthetic_row(), empty_source_row(empty_value)])

    findings, anomalies, stats = parse_findings(path)

    assert stats["input_rows"] == 2
    assert stats["analyzed_rows"] == 1
    assert stats["ignored_empty_rows"] == 1
    assert stats["output_findings"] == 1
    assert not any(anomaly.row_index == 1 for anomaly in anomalies)
    assert len(findings) == 1


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    [
        ({"AUID": "", "CODE_APP": ""}, "INVALID_OR_MISSING_AUID"),
        ({"CVE": ""}, "INVALID_CVE"),
        ({"Month": "not-a-date"}, "INVALID_DATE"),
    ],
)
def test_partially_filled_row_remains_analyzed_and_in_error(
    csv_factory, overrides, expected_error,
):
    path = csv_factory([synthetic_row(**overrides)])

    findings, anomalies, stats = parse_findings(path)

    assert stats["input_rows"] == 1
    assert stats["analyzed_rows"] == 1
    assert stats["ignored_empty_rows"] == 0
    assert stats["output_findings"] == 1
    error = next(
        anomaly
        for anomaly in anomalies
        if anomaly.severity == "ERROR" and anomaly.error_type == expected_error
    )
    assert error.row_index == 0
    assert error.source_row_number == 2
    assert len(findings) == 1


def test_anomaly_indexes_are_zero_based_and_never_equal_input_row_count(csv_factory):
    rows = [
        synthetic_row(REM_KEY_ID="ROW-1"),
        synthetic_row(REM_KEY_ID="ROW-2"),
        synthetic_row(REM_KEY_ID="ROW-3", CVE=""),
    ]

    _, anomalies, stats = parse_findings(csv_factory(rows))

    final_error = next(
        anomaly
        for anomaly in anomalies
        if anomaly.severity == "ERROR" and anomaly.error_type == "INVALID_CVE"
    )
    assert final_error.row_index == stats["input_rows"] - 1 == 2
    assert final_error.source_row_number == 4
    assert all(0 <= anomaly.row_index < stats["input_rows"] for anomaly in anomalies)
    assert all(
        anomaly.source_row_number == anomaly.row_index + 2
        for anomaly in anomalies
    )


def test_empty_middle_row_preserves_index_for_kri_source_control(csv_factory):
    rows = [
        synthetic_row(REM_KEY_ID="ROW-1", HOSTNAME="host-first"),
        empty_source_row(),
        synthetic_row(
            REM_KEY_ID="ROW-3",
            HOSTNAME="host-last",
            AGE="999",
            **{"KRI RAS 9": "false"},
        ),
    ]

    _, anomalies, stats = parse_findings(csv_factory(rows))

    mismatch = next(
        anomaly
        for anomaly in anomalies
        if anomaly.error_type == "KRI_SERVER_MISMATCH"
        and anomaly.rem_key_id == "ROW-3"
    )
    assert mismatch.row_index == 2
    assert mismatch.source_row_number == 4
    assert stats["input_rows"] == 3
    assert stats["analyzed_rows"] == 2
    assert stats["ignored_empty_rows"] == 1
    assert stats["output_findings"] == 2


def test_parser_anomalies_json_contains_both_row_coordinates(csv_factory, tmp_path):
    findings, anomalies, stats = parse_findings(csv_factory([
        synthetic_row(CVE=""),
    ]))

    paths = write_outputs(findings, anomalies, stats, tmp_path)
    payload = json.loads(paths["anomalies"].read_text(encoding="utf-8"))
    cve_error = next(item for item in payload if item["error_type"] == "INVALID_CVE")

    assert cve_error["row_index"] == 0
    assert cve_error["source_row_number"] == 2

