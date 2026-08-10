from datetime import date

import pytest

from src.parser import parse_findings
from tests.conftest import synthetic_row


@pytest.mark.parametrize(
    "target",
    ["/apps/oracle/test/file", "/appli/test/file", "/etc/test/file", None],
)
def test_xtract_path_is_copied_without_business_validation(csv_factory, target):
    findings, anomalies, _ = parse_findings(csv_factory([synthetic_row(XTRACT_PATH=target)]))
    assert findings[0].target == target
    assert findings[0].remediation_strategy.ownership_main is None
    assert not any(item.error_type == "INVALID_TARGET" for item in anomalies)


@pytest.mark.parametrize("eta", [None, "", "NULL", "null", "N/A"])
def test_missing_eta_is_none_without_invalid_date(csv_factory, eta):
    findings, anomalies, _ = parse_findings(csv_factory([synthetic_row(ETA=eta)]))
    assert findings[0].eta is None
    assert not any(item.field == "ETA" and item.error_type == "INVALID_DATE" for item in anomalies)


def test_valid_eta_is_parsed(csv_factory):
    findings, anomalies, _ = parse_findings(csv_factory([synthetic_row(ETA="2026-06-30")]))
    assert findings[0].eta == date(2026, 6, 30)
    assert not any(item.field == "ETA" and item.error_type == "INVALID_DATE" for item in anomalies)


@pytest.mark.parametrize("eta", ["bonjour", "xx/99/9999"])
def test_non_empty_invalid_eta_generates_invalid_date(csv_factory, eta):
    findings, anomalies, _ = parse_findings(csv_factory([synthetic_row(ETA=eta)]))
    assert findings[0].eta is None
    assert any(item.field == "ETA" and item.error_type == "INVALID_DATE" for item in anomalies)
