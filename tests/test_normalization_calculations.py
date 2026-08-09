from datetime import date

from src.calculations.finding_calculations import (
    calculate_age, calculate_overdue, calculate_server_sensitivity, calculate_sla,
)
from src.parser import (
    normalize_as_of_date, normalize_environment, normalize_first_detection,
    normalize_operating_system,
)


def test_as_of_date_documented_formats():
    current = date(2026, 6, 13)
    assert normalize_as_of_date("May", current)[0] == date(2026, 5, 13)
    assert normalize_as_of_date("May 2026", current)[0] == date(2026, 5, 13)
    assert normalize_as_of_date("5", current)[0] == date(2026, 5, 13)
    assert normalize_as_of_date("5-2", current)[0] == date(2026, 5, 2)
    assert normalize_as_of_date("26-5-2", current)[0] == date(2026, 5, 2)
    assert normalize_as_of_date("2/5/26", current)[0] == date(2026, 5, 2)


def test_environment_mapping_and_unknown():
    assert normalize_environment("INTEGRATION / PRE-RECETTE") == ("INTEGRATION", "NON-PRODUCTION")
    assert normalize_environment("unknown") == (None, None)


def test_os_parsing_and_fallback():
    assert normalize_operating_system("RHEL_9.6", None) == ("RHEL", "9.6")
    assert normalize_operating_system("RHEL", "RHEL_7.9") == ("RHEL", "7.9")


def test_first_detection_fallback():
    value, fallback = normalize_first_detection(None, "2026-05-02")
    assert value == date(2026, 5, 2) and fallback is True


def test_age_sla_overdue_and_sensitivity():
    age, recalculated = calculate_age(date(2026, 5, 1), date(2026, 5, 13), "12", date(2026, 6, 13))
    assert (age, recalculated) == (12, False)
    sla, deduced = calculate_sla(None, "P4", None, "PRODUCTION", "Very High")
    assert (sla, deduced) == (90, True)
    assert calculate_overdue(91, 90) is True
    assert calculate_server_sensitivity("P3", None, None, "BACKUP") is True
    assert calculate_server_sensitivity("P3", None, None, "RECETTE") is False
