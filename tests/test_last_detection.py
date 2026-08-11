from datetime import date

import pytest

from src.parser import parse_findings
from tests.conftest import synthetic_row


@pytest.mark.parametrize("last_found", ["2026-06-25", "2026-07-25"])
def test_last_detection_month_does_not_need_to_match_as_of_date(
    csv_factory, last_found
):
    row = synthetic_row(
        Month="July",
        LAST_FOUND_DATE=last_found,
        ABSOLUTE_FIRST_FOUND_DATE="2026-06-01",
        AGE="",
    )
    findings, anomalies, _ = parse_findings(csv_factory([row]))

    assert findings[0].last_detection == date.fromisoformat(last_found)
    assert not any(
        item.field == "LAST_FOUND_DATE" and item.severity == "ERROR"
        for item in anomalies
    )
    assert not any(
        item.error_type == "LAST_DETECTION_MONTH_MISMATCH"
        for item in anomalies
    )


def test_invalid_last_detection_remains_a_technical_error(csv_factory):
    row = synthetic_row(Month="July", LAST_FOUND_DATE="invalid")
    findings, anomalies, _ = parse_findings(csv_factory([row]))

    assert findings[0].last_detection is None
    assert any(
        item.field == "LAST_FOUND_DATE"
        and item.severity == "ERROR"
        and item.error_type == "INVALID_DATE"
        for item in anomalies
    )
