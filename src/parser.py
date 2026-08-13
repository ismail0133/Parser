import time
from datetime import date, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from src.calculations.finding_calculations import (
    calculate_age,
    calculate_kri_ras9,
    calculate_global_kri_ras9,
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
from src.validation.finding_validator import AUID_PATTERN, classify_anomaly, validate_finding_payload
from src.validation.retry import MAX_PARSE_ATTEMPTS


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
                   value=value, severity=severity, error_type=error_type, message=message,
                   classification=classify_anomaly(severity, error_type))


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
    as_of_date, inferred_as_of = normalize_as_of_date(row.get("Month"), current_date)
    if inferred_as_of:
        anomalies.append(_anomaly(row_index, rem_id, "Month", row.get("Month"),
                                  "INFO", "AS_OF_DATE_INFERRED", "Missing date parts were completed from current_date"))
    elif as_of_date is None:
        anomalies.append(_anomaly(row_index, rem_id, "Month", row.get("Month"),
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
    target = direct["target"]
    priority = direct["priority"]
    if normalize_string(row.get("PRIORITY")) and priority is None:
        anomalies.append(_anomaly(row_index, rem_id, "PRIORITY", row.get("PRIORITY"),
                                  "ERROR", "UNKNOWN_PRIORITY", "Priority must be PR1, PR2, PR3 or PR4"))

    payload: dict[str, Any] = {
        "unique_id": direct["cve"],
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
        "ownership": direct["proposed_owner"],
        "remediation_strategy": {"description": direct["action_plan"], "strategy_type": None,
                                 "ownership_main": None},
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
    eta_source = normalize_string(row.get("ETA"))
    payload["eta"] = None if direct["false_positive"] or eta_source is None else _parse_eta(eta_source)
    if not direct["false_positive"] and eta_source is not None and payload["eta"] is None:
        anomalies.append(_anomaly(row_index, rem_id, "ETA", row.get("ETA"), "ERROR",
                                  "INVALID_DATE", "eta cannot be parsed"))
    if rem_id is None:
        anomalies.append(_anomaly(
            row_index, rem_id, "REM_KEY_ID", None, "WARNING",
            "MISSING_REMEDIATION_ID",
            "REM_KEY_ID absent. Verify whether the finding was removed, corrected, or the identifier is unavailable in the source.",
        ))
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
    if kri["status"] == "NOT_COMPUTABLE":
        anomalies.append(_anomaly(
            row_index, rem_id, "KRI RAS 9", row.get("KRI RAS 9"), "WARNING",
            "KRI_NOT_COMPUTABLE",
            "KRI RAS 9 cannot be computed; missing: " + ", ".join(kri["missing_fields"]),
        ))
    return finding, anomalies, kri


def _validate_server_kri_sources(
    frame: pd.DataFrame, findings: list[Finding], parsed_row_positions: list[int]
) -> tuple[list[Anomaly], dict[str, Any]]:
    server_rows: dict[str, list[tuple[int, Any, Finding]]] = {}
    for finding, row_index in zip(findings, parsed_row_positions):
        row = frame.iloc[row_index - 1]
        if finding.hostname:
            server_rows.setdefault(finding.hostname, []).append(
                (row_index, row.get("KRI RAS 9"), finding)
            )

    anomalies: list[Anomaly] = []
    servers_checked = 0
    inconsistencies = 0
    mismatches = 0
    uninterpretable = 0
    for hostname, rows in server_rows.items():
        raw_values = [value for _, value, _ in rows if normalize_string(value) is not None]
        parsed_values = {parse_source_kri(value) for value in raw_values}
        interpreted_values = {value for value in parsed_values if value is not None}
        first_row, _, first_finding = rows[0]
        if raw_values:
            servers_checked += 1
        if None in parsed_values:
            uninterpretable += 1
            anomalies.append(_anomaly(
                first_row, first_finding.remediation_id, "KRI RAS 9", raw_values,
                "WARNING", "KRI_SOURCE_SERVER_UNINTERPRETABLE",
                f"Server {hostname} has a source KRI value that cannot be interpreted.",
            ))
            continue
        if len(interpreted_values) > 1:
            inconsistencies += 1
            anomalies.append(_anomaly(
                first_row, first_finding.remediation_id, "KRI RAS 9",
                {"hostname": hostname, "values_found": raw_values, "number_of_findings": len(rows)},
                "WARNING", "KRI_SOURCE_SERVER_INCONSISTENT",
                f"Server {hostname} has contradictory source KRI values across {len(rows)} findings.",
            ))
            continue
        if not interpreted_values:
            continue
        server_eligible = any(
            finding.server.sensitive is True and finding.server.authenticated_scan is True
            for _, _, finding in rows
        )
        server_result = bool(server_eligible and any(
            finding.server.sensitive is True
            and finding.server.authenticated_scan is True
            and finding.severity_level
            and finding.severity_level.casefold() in {"critical", "very high"}
            and finding.overdue is True
            and finding.false_positive is not True
            for _, _, finding in rows
        ))
        source_result = next(iter(interpreted_values))
        if source_result != server_result:
            mismatches += 1
            anomalies.append(_anomaly(
                first_row, first_finding.remediation_id, "KRI RAS 9",
                {"hostname": hostname, "source": source_result, "calculated": server_result},
                "WARNING", "KRI_SERVER_MISMATCH",
                f"Source KRI for server {hostname} differs from the calculated server-level KRI.",
            ))
    return anomalies, {
        "source_kri_servers_checked": servers_checked,
        "source_inconsistencies": inconsistencies,
        "server_level_mismatches": mismatches,
        "source_uninterpretable": uninterpretable,
        "automatically_correctable": 0,
    }


def parse_findings(path: str | Path, application_lookup: ApplicationLookup | None = None,
                   limit: int | None = None) -> tuple[list[Finding], list[Anomaly], dict[str, Any]]:
    started = time.perf_counter()
    frame = clean_findings(load_findings(path, limit=limit))
    findings: list[Finding] = []
    anomalies: list[Anomaly] = []
    kri_evaluations: list[dict[str, Any]] = []
    parsed_row_positions: list[int] = []
    rows_with_warnings: set[int] = set()
    rows_with_errors: set[int] = set()
    for position, (_, series) in enumerate(frame.iterrows(), start=1):
        try:
            finding, row_anomalies, kri = _parse_row(position, series.to_dict(), application_lookup, date.today())
            findings.append(finding)
            parsed_row_positions.append(position)
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
    server_kri_anomalies, server_kri_control = _validate_server_kri_sources(
        frame, findings, parsed_row_positions
    )
    anomalies.extend(server_kri_anomalies)
    rows_with_warnings.update(item.row_index for item in server_kri_anomalies)
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
        "retry": {
            "retry_count": 0,
            "max_attempts": MAX_PARSE_ATTEMPTS,
            "attempts": [],
            "reason": "No current parser ERROR has a confirmed deterministic post-parse correction",
        },
        "application_enrichment": {
            "status": "SKIPPED_NO_SOURCE" if application_lookup is None else "APPLIED",
        },
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
    stats["kri_ras9"]["aggregate"] = calculate_global_kri_ras9(findings)
    stats["kri_ras9"]["server_source_control"] = server_kri_control
    return findings, anomalies, stats
