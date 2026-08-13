from copy import deepcopy

import pytest

from src.calculations.finding_calculations import (
    calculate_global_kri_ras9, categorize_kri_ras9, is_kri_business_target_met,
)
from src.models import Finding
from src.parser import parse_findings
from tests.conftest import synthetic_row


def _finding(csv_factory, **changes):
    findings, _, _ = parse_findings(csv_factory([synthetic_row()]))
    payload = findings[0].model_dump()
    for key, value in changes.items():
        if key.startswith("server__"):
            payload["server"][key.removeprefix("server__")] = value
        else:
            payload[key] = value
    return Finding.model_validate(payload)


@pytest.mark.parametrize(
    ("authenticated_scan", "expected_denominator", "expected_numerator"),
    [(True, 1, 1), (False, 0, 0), (None, 0, 0)],
)
def test_global_kri_requires_authenticated_scan(
    csv_factory, authenticated_scan, expected_denominator, expected_numerator
):
    finding = _finding(
        csv_factory,
        server__sensitive=True,
        server__authenticated_scan=authenticated_scan,
        severity_level="Critical",
        overdue=True,
        false_positive=False,
    )
    result = calculate_global_kri_ras9([finding])
    assert result["eligible_sensitive_authenticated_servers"] == expected_denominator
    assert result["servers_with_overdue_critical_or_very_high"] == expected_numerator


def test_non_overdue_server_is_only_in_denominator(csv_factory):
    finding = _finding(csv_factory, server__sensitive=True, server__authenticated_scan=True, overdue=False)
    result = calculate_global_kri_ras9([finding])
    assert result["eligible_sensitive_authenticated_servers"] == 1
    assert result["servers_with_overdue_critical_or_very_high"] == 0


def test_false_positive_is_excluded_from_numerator(csv_factory):
    finding = _finding(
        csv_factory, server__sensitive=True, server__authenticated_scan=True,
        severity_level="Very High", overdue=True, false_positive=True,
    )
    result = calculate_global_kri_ras9([finding])
    assert result["eligible_sensitive_authenticated_servers"] == 1
    assert result["servers_with_overdue_critical_or_very_high"] == 0


def test_same_hostname_is_counted_once(csv_factory):
    finding = _finding(
        csv_factory, server__sensitive=True, server__authenticated_scan=True,
        severity_level="Critical", overdue=True, false_positive=False,
    )
    duplicate = Finding.model_validate(deepcopy(finding.model_dump()))
    result = calculate_global_kri_ras9([finding, duplicate])
    assert result["eligible_sensitive_authenticated_servers"] == 1
    assert result["servers_with_overdue_critical_or_very_high"] == 1


def test_no_eligible_server_is_not_computable(csv_factory):
    finding = _finding(csv_factory, server__sensitive=True, server__authenticated_scan=None)
    result = calculate_global_kri_ras9([finding])
    assert result["status"] == "NOT_COMPUTABLE"
    assert result["percentage"] is None
    assert result["category"] is None


@pytest.mark.parametrize(
    ("percentage", "category"),
    [(0, "PERFECT"), (5, "EXCELLENT"), (20, "SATISFACTORY"),
     (40, "UNSATISFACTORY"), (60, "CRITICAL")],
)
def test_kri_categories(percentage, category):
    assert categorize_kri_ras9(percentage) == category


@pytest.mark.parametrize(
    ("percentage", "expected"),
    [(29.99, True), (30.0, False), (40.0, False)],
)
def test_kri_business_target_is_strictly_below_30(percentage, expected):
    assert is_kri_business_target_met(percentage) is expected


def test_zero_denominator_has_no_business_target_result(csv_factory):
    finding = _finding(csv_factory, server__sensitive=False)
    result = calculate_global_kri_ras9([finding])
    assert result["status"] == "NOT_COMPUTABLE"
    assert result["percentage"] is None
    assert result["business_target_met"] is None
