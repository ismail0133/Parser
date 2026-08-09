import time
from datetime import date, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from src.calculations.finding_calculations import (
    calculate_age,
    calculate_kri_ras9,
    calculate_overdue,
    calculate_server_sensitivity,
    calculate_sla,
    parse_source_kri,
)
from src.cleaning.finding_cleaner import clean_findings, normalize_string
from src.enrichment.application_enricher import ApplicationLookup, enrich_with_application
from src.loaders.finding_loader import EXPECTED_COLUMNS, load_findings
from src.mapping.finding_mapper import map_direct_fields
from src.models.finding import Anomaly, Finding
from src.validation.finding_validator import AUID_PATTERN, validate_finding_payload


ENVIRONMENT_MAPPING = {
    "PRODUCTION": ("PRODUCTION", "PRODUCTION"),
    "PRE-PRODUCTION": ("PRE-PRODUCTION", "PRODUCTION"),
    "BACKUP": ("BACKUP", "PRODUCTION"),
    "INTEGRATION / PRE-RECETTE": ("INTEGRATION", "NON-PRODUCTION"),
    "RECETTE": ("RECETTE", "NON-PRODUCTION"),
    "DEVELOPPEMENT": ("DEVELOPPEMENT", "NON-PRODUCTION"),
    "QUALIFICATION": ("QUALIFICATION", "NON-PRODUCTION"),
}
MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5,
    "june": 6, "july": 7, "august": 8, "september": 9, "october": 10,
    "november": 11, "december": 12,
}


def _anomaly(row_index: int, rem_key_id: str | None, field: str, value: Any,
             severity: str, error_type: str, message: str) -> Anomaly:
    return Anomaly(row_index=row_index, rem_key_id=rem_key_id, field=field,
                   value=value, severity=severity, error_type=error_type, message=message)


def normalize_as_of_date(value: Any, current_date: date) -> tuple[date | None, bool]:
    text = normalize_string(value)
    if not text:
        return None, False
    lower = text.casefold()
    if lower in MONTHS:
        return date(current_date.year, MONTHS[lower], current_date.day), True
    words = lower.split()
    if len(words) == 2 and words[0] in MONTHS and words[1].isdigit():
        return date(int(words[1]), MONTHS[words[0]], current_date.day), True
    slash_separated = "/" in text
    parts = text.replace("/", "-").split("-")
    try:
        if len(parts) == 1 and parts[0].isdigit():
            return date(current_date.year, int(parts[0]), current_date.day), True
        if len(parts) == 2:
            if parts[0].casefold() in MONTHS:
                return date(int(parts[1]), MONTHS[parts[0].casefold()], current_date.day), True
            return date(current_date.year, int(parts[0]), int(parts[1])), True
        if len(parts) == 3:
            first = int(parts[0])
            if not slash_separated:  # documented hyphen form is year-month-day
                year = first + 2000 if first < 100 else first
                return date(year, int(parts[1]), int(parts[2])), first < 100
            year = int(parts[2])
            year = year + 2000 if year < 100 else year
            return date(year, int(parts[1]), int(parts[0])), int(parts[2]) < 100
        parsed = pd.to_datetime(text, errors="raise")
        return parsed.date(), False
    except (ValueError, TypeError, OverflowError):
        return None, False


def normalize_environment(value: Any) -> tuple[str | None, str | None]:
    text = normalize_string(value)
    return ENVIRONMENT_MAPPING.get(text.upper(), (None, None)) if text else (None, None)


def normalize_operating_system(primary: Any, fallback: Any) -> tuple[str | None, str | None]:
    def parse(value: Any) -> tuple[str | None, str | None]:
        text = normalize_string(value)
        if not text:
            return None, None
        tokens = [token.strip() for token in text.split("_") if token.strip()]
        names = [token for token in tokens if not token.replace(".", "", 1).isdigit()]
        versions = [token for token in tokens if token.replace(".", "", 1).isdigit()]
        return ("_".join(names) or None, versions[-1] if versions else None)
    os_name, os_version = parse(primary)
    if os_name is not None and os_version is not None:
        return os_name, os_version
    fallback_name, fallback_version = parse(fallback)
    return os_name or fallback_name, os_version or fallback_version


def _normalize_date(value: Any) -> date | None:
    text = normalize_string(value)
    if not text:
        return None
    # ISO year-first is unambiguous; documented slash/day-first inputs use dayfirst.
    parsed = pd.to_datetime(text, errors="coerce", dayfirst=not (len(text) >= 10 and text[4:5] == "-"))
    return None if pd.isna(parsed) else parsed.date()


def normalize_first_detection(absolute_value: Any, fallback_value: Any) -> tuple[date | None, bool]:
    primary = _normalize_date(absolute_value)
    if primary is not None:
        return primary, False
    fallback = _normalize_date(fallback_value)
    return fallback, fallback is not None


def normalize_last_detection(value: Any) -> date | None:
    return _normalize_date(value)


def _parse_eta(value: Any) -> date | None:
    return _normalize_date(value)


def _valid_auid(value: Any) -> str | None:
    text = normalize_string(value)
    return text.upper() if text and AUID_PATTERN.fullmatch(text) else None


def _parse_row(row_index: int, row: dict[str, Any], application_lookup: ApplicationLookup | None,
               current_date: date) -> tuple[Finding, list[Anomaly], dict[str, Any]]:
    anomalies: list[Anomaly] = []
    direct = map_direct_fields(row)
    rem_id = direct["remediation_id"]
    as_of_date, inferred_as_of = normalize_as_of_date(row.get("REPORTDATE - Month"), current_date)
    if inferred_as_of:
        anomalies.append(_anomaly(row_index, rem_id, "REPORTDATE - Month", row.get("REPORTDATE - Month"),
                                  "INFO", "AS_OF_DATE_INFERRED", "Missing date parts were completed from current_date"))
    elif as_of_date is None:
        anomalies.append(_anomaly(row_index, rem_id, "REPORTDATE - Month", row.get("REPORTDATE - Month"),
                                  "ERROR", "INVALID_DATE", "as_of_date cannot be determined"))

    environment_detail, environment = normalize_environment(row.get("ENVIRONMENT"))
    if normalize_string(row.get("ENVIRONMENT")) and environment is None:
        anomalies.append(_anomaly(row_index, rem_id, "ENVIRONMENT", row.get("ENVIRONMENT"),
                                  "ERROR", "UNKNOWN_ENVIRONMENT", "Environment is not in the documented mapping"))
    os_name, os_version = normalize_operating_system(
        row.get("OPERATING_SYSTEM"), row.get("AFFECTED_PLATFORMS")
    )
    auid = _valid_auid(row.get("AUID"))
    if auid is None:
        auid = _valid_auid(row.get("CODE_APP"))
        if auid is not None:
            anomalies.append(_anomaly(row_index, rem_id, "CODE_APP", row.get("CODE_APP"),
                                      "INFO", "AUID_FALLBACK_USED", "CODE_APP supplied application.auid"))

    first_detection, used_fallback = normalize_first_detection(
        row.get("ABSOLUTE_FIRST_FOUND_DATE"), row.get("FIRST_FOUND_DATE")
    )
    if used_fallback:
        anomalies.append(_anomaly(row_index, rem_id, "FIRST_FOUND_DATE", row.get("FIRST_FOUND_DATE"),
                                  "INFO", "FIRST_DETECTION_FALLBACK", "FIRST_FOUND_DATE used as fallback"))
    last_detection = normalize_last_detection(row.get("LAST_FOUND_DATE"))
    if normalize_string(row.get("LAST_FOUND_DATE")) and last_detection is None:
        anomalies.append(_anomaly(row_index, rem_id, "LAST_FOUND_DATE", row.get("LAST_FOUND_DATE"),
                                  "ERROR", "INVALID_DATE", "last_detection cannot be parsed"))
    if last_detection and as_of_date and (last_detection.year, last_detection.month) != (as_of_date.year, as_of_date.month):
        anomalies.append(_anomaly(row_index, rem_id, "LAST_FOUND_DATE", row.get("LAST_FOUND_DATE"),
                                  "ERROR", "LAST_DETECTION_MONTH_MISMATCH",
                                  "last_detection month is inconsistent with as_of_date"))

    target = direct["target"]
    ownership_main = "APS" if target and target.casefold().startswith("/appli/") else None
    if target and ownership_main is None:
        anomalies.append(_anomaly(row_index, rem_id, "XTRACT_PATH", target, "ERROR",
                                  "INVALID_TARGET", "target does not start with /appli/"))
    priority = direct["priority"]
    if normalize_string(row.get("PRIORITY")) and priority is None:
        anomalies.append(_anomaly(row_index, rem_id, "PRIORITY", row.get("PRIORITY"),
                                  "ERROR", "UNKNOWN_PRIORITY", "Priority must be PR1, PR2, PR3 or PR4"))

    payload: dict[str, Any] = {
        "as_of_date": as_of_date,
        "remediation_id": rem_id,
        "hostname": direct["hostname"],
        "server": {"os_name": os_name, "os_version": os_version,
                   "environment_detail": environment_detail, "environment": environment},
        "application": {"auid": auid, "trigram": direct["application_trigram"],
                        "name": direct["application_name"], "appsec": direct["application_appsec"],
                        "vital": None, "cis": None},
        "cve": direct["cve"],
        "cve_detail": {"title": direct["cve_title"], "solution_links": direct["solution_links"]},
        "priority": priority,
        "affected_component": direct["affected_component"],
        "affected_product": direct["affected_product"],
        "target": target,
        "first_detection": first_detection,
        "last_detection": last_detection,
        "business_line": direct["business_line"],
        "severity_level": direct["severity_level"],
        "proposed_action": direct["proposed_action"],
        "ownership": None,
        "remediation_strategy": {"description": direct["action_plan"], "strategy_type": None,
                                 "ownership_main": ownership_main},
        "false_positive": direct["false_positive"],
        "false_positive_to_confirm": direct["false_positive_to_confirm"],
    }
    payload, enriched = enrich_with_application(payload, application_lookup)
    if application_lookup is not None and auid and not enriched:
        anomalies.append(_anomaly(row_index, rem_id, "application", auid, "WARNING",
                                  "APPLICATION_NOT_FOUND", "No Application enrichment found for AUID"))

    age, age_recalculated = calculate_age(first_detection, as_of_date, row.get("AGE"), current_date)
    if age_recalculated:
        anomalies.append(_anomaly(row_index, rem_id, "AGE", row.get("AGE"), "INFO",
                                  "AGE_RECALCULATED", "age was recalculated from current_date and first_detection"))
    application = payload["application"]
    sla, sla_deduced = calculate_sla(row.get("SLA"), application.get("appsec"),
                                     application.get("vital"), environment, direct["severity_level"])
    if sla_deduced:
        anomalies.append(_anomaly(row_index, rem_id, "SLA", row.get("SLA"), "INFO",
                                  "SLA_DEDUCED", "sla was deduced from documented rules"))
    overdue = calculate_overdue(age, sla)
    payload.update({"age": age, "sla": sla, "overdue": overdue})
    payload["server"]["sensitive"] = calculate_server_sensitivity(
        application.get("appsec"), application.get("vital"), application.get("cis"), environment_detail
    )
    payload["eta"] = None if direct["false_positive"] else _parse_eta(row.get("ETA"))
    if not direct["false_positive"] and normalize_string(row.get("ETA")) and payload["eta"] is None:
        anomalies.append(_anomaly(row_index, rem_id, "ETA", row.get("ETA"), "ERROR",
                                  "INVALID_DATE", "eta cannot be parsed"))
    if rem_id is None:
        anomalies.append(_anomaly(row_index, rem_id, "REM_KEY_ID", None, "ERROR",
                                  "TO_VALIDATE_REMEDIATION_ID", "remediation_id fallback formula is unavailable"))
    for field, error_type, message in validate_finding_payload(payload):
        anomalies.append(_anomaly(row_index, rem_id, field, row.get(field), "ERROR", error_type, message))
    finding = Finding.model_validate(payload)
    kri = calculate_kri_ras9(
        hostname=finding.hostname,
        server_sensitive=finding.server.sensitive,
        severity_level=finding.severity_level,
        overdue=finding.overdue,
        false_positive=finding.false_positive,
    )
    source_kri = parse_source_kri(row.get("KRI RAS 9"))
    if kri["status"] == "NOT_COMPUTABLE":
        anomalies.append(_anomaly(
            row_index, rem_id, "KRI RAS 9", row.get("KRI RAS 9"), "WARNING",
            "KRI_NOT_COMPUTABLE",
            "KRI RAS 9 cannot be computed; missing: " + ", ".join(kri["missing_fields"]),
        ))
    elif source_kri is not None and source_kri != kri["result"]:
        anomalies.append(_anomaly(
            row_index, rem_id, "KRI RAS 9", row.get("KRI RAS 9"), "WARNING",
            "KRI_MISMATCH", "Source KRI differs from calculated KRI",
        ))
    return finding, anomalies, kri


def parse_findings(path: str | Path, application_lookup: ApplicationLookup | None = None,
                   limit: int | None = None) -> tuple[list[Finding], list[Anomaly], dict[str, Any]]:
    started = time.perf_counter()
    frame = clean_findings(load_findings(path, limit=limit))
    findings: list[Finding] = []
    anomalies: list[Anomaly] = []
    kri_evaluations: list[dict[str, Any]] = []
    rows_with_warnings: set[int] = set()
    rows_with_errors: set[int] = set()
    for position, (_, series) in enumerate(frame.iterrows(), start=1):
        try:
            finding, row_anomalies, kri = _parse_row(position, series.to_dict(), application_lookup, date.today())
            findings.append(finding)
            kri_evaluations.append(kri)
            anomalies.extend(row_anomalies)
            if any(item.severity == "WARNING" for item in row_anomalies):
                rows_with_warnings.add(position)
            if any(item.severity == "ERROR" for item in row_anomalies):
                rows_with_errors.add(position)
        except Exception as exc:  # keep one malformed row from stopping the batch
            anomalies.append(_anomaly(position, normalize_string(series.get("REM_KEY_ID")), "row", None,
                                      "ERROR", "ROW_BUILD_ERROR", str(exc)))
            rows_with_errors.add(position)
    counts = {severity: sum(item.severity == severity for item in anomalies)
              for severity in ("INFO", "WARNING", "ERROR")}
    stats = {
        "input_rows": len(frame),
        "input_columns": len(EXPECTED_COLUMNS),
        "parsed_successfully": len(frame) - len(rows_with_errors) - len(rows_with_warnings - rows_with_errors),
        "parsed_with_warnings": len(rows_with_warnings),
        "parsed_with_errors": len(rows_with_errors),
        "output_findings": len(findings),
        "info_count": counts["INFO"],
        "warning_count": counts["WARNING"],
        "error_count": counts["ERROR"],
        "duration_seconds": round(time.perf_counter() - started, 6),
        "kri_ras9": {
            "status": (
                "COMPUTED" if kri_evaluations and all(item["status"] == "COMPUTED" for item in kri_evaluations)
                else "NOT_COMPUTABLE"
            ),
            "authenticated_scan_default": True,
            "computed_findings": sum(item["status"] == "COMPUTED" for item in kri_evaluations),
            "not_computable_findings": sum(item["status"] == "NOT_COMPUTABLE" for item in kri_evaluations),
            "qualifying_findings": sum(item.get("result") is True for item in kri_evaluations),
            "missing_fields": sorted({field for item in kri_evaluations for field in item["missing_fields"]}),
        },
    }
    return findings, anomalies, stats
