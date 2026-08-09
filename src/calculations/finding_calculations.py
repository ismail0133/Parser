from datetime import date
from typing import Any


def calculate_age(
    first_detection: date | None,
    as_of_date: date | None,
    csv_age: Any,
    current_date: date,
) -> tuple[int | None, bool]:
    """Return age and whether the documented recalculation rule was used."""
    if first_detection is None:
        return None, False
    expected = (as_of_date - first_detection).days if as_of_date else None
    try:
        provided = int(float(str(csv_age))) if csv_age is not None else None
    except (TypeError, ValueError):
        provided = None
    if provided is not None and expected is not None and provided == expected:
        return provided, False
    return (current_date - first_detection).days, True


def _is_vital(value: bool | str | None) -> bool:
    if value is True:
        return True
    return isinstance(value, str) and value.strip().upper() in {"TRUE", "ACTIF", "ACTIVE", "GROUPE", "BUSINESS"}


def calculate_sla(
    csv_sla: Any,
    appsec: str | None,
    vital: bool | str | None,
    environment: str | None,
    severity_level: str | None,
) -> tuple[int | None, bool]:
    try:
        if csv_sla is not None:
            return int(float(str(csv_sla))), False
    except (TypeError, ValueError):
        pass
    appsec_value = appsec.upper() if appsec else None
    severity = severity_level.casefold() if severity_level else None
    if appsec_value == "P4":
        return 90, True
    if _is_vital(vital) and environment == "PRODUCTION" and severity == "very high":
        return 90, True
    if _is_vital(vital) and environment == "PRODUCTION" and severity == "high":
        return 180, True
    if severity == "very high":
        return 180, True
    if severity == "high":
        return 365, True
    return None, False


def calculate_overdue(age: int | None, sla: int | None) -> bool | None:
    return None if age is None or sla is None else age > sla


def calculate_server_sensitivity(
    appsec: str | None,
    vital: bool | str | None,
    cis: bool | None,
    environment_detail: str | None,
) -> bool:
    application_sensitive = (
        (appsec or "").upper() in {"P4", "P3"}
        or (isinstance(vital, str) and vital.upper() in {"GROUPE", "BUSINESS"})
        or cis is True
    )
    return application_sensitive and environment_detail in {"PRODUCTION", "BACKUP"}


def calculate_kri_ras9(
    *,
    hostname: str | None,
    server_sensitive: bool,
    severity_level: str | None,
    overdue: bool | None,
    false_positive: bool,
    authenticated_scan: bool = True,
) -> dict[str, Any]:
    """Evaluate the documented per-finding KRI condition.

    The CSV has no explicit scan-authentication field. The documentation states
    that a scan is authenticated by default unless explicitly stated otherwise.
    No aggregate rate or score is inferred here.
    """
    missing: list[str] = []
    if not hostname:
        missing.append("hostname")
    if not severity_level:
        missing.append("severity_level")
    if overdue is None:
        missing.append("overdue")
    if missing:
        return {"status": "NOT_COMPUTABLE", "result": None, "missing_fields": missing}
    result = bool(
        server_sensitive
        and authenticated_scan
        and severity_level.casefold() in {"critical", "very high"}
        and overdue
        and not false_positive
    )
    return {"status": "COMPUTED", "result": result, "missing_fields": []}


def parse_source_kri(value: Any) -> bool | None:
    """Parse only unambiguous boolean-like source values for control purposes."""
    if value is None:
        return None
    normalized = str(value).strip().casefold()
    if normalized in {"true", "yes", "y", "1"}:
        return True
    if normalized in {"false", "no", "n", "0"}:
        return False
    return None
