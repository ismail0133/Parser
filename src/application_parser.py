"""Dedicated RAW dataframe to canonical obj_application parser."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from src.cleaning.finding_cleaner import normalize_string
from src.models.application import ApplicationAnomaly, ObjApplication
from src.validation.finding_validator import validate_auid


APPLICATION_COLUMN_MAPPING = {
    "CODE_APP": "code_app",
    "Legacy APP ID": "trigram",
    "Application Name": "application_name",
    "AppSec Profile": "appsec",
    "Business Lines": "business_line",
    "Production Domain Manager": "production_domain_manager",
    "Production Manager": "production_manager",
}


def _canonical_value(values: Iterable[Any]) -> tuple[Any | None, list[Any]]:
    distinct = sorted(
        {value for raw in values if (value := normalize_string(raw)) is not None}
    )
    return (distinct[0], []) if len(distinct) == 1 else (None, distinct)


def parse_applications(
    frame: pd.DataFrame,
) -> tuple[list[ObjApplication], list[ApplicationAnomaly], dict[str, Any]]:
    """Build one Application per valid AUID without choosing conflicting values."""
    required = ["AUID", *APPLICATION_COLUMN_MAPPING]
    missing_columns = [column for column in required if column not in frame.columns]
    if missing_columns:
        raise ValueError(f"Missing Application CSV columns: {missing_columns}")

    anomalies: list[ApplicationAnomaly] = []
    rows_by_auid: dict[str, list[int]] = {}
    missing_auid_rows = 0
    invalid_auid_rows = 0
    for position, value in enumerate(frame["AUID"].tolist(), start=1):
        normalized = normalize_string(value)
        if normalized is None:
            missing_auid_rows += 1
            anomalies.append(ApplicationAnomaly(
                error_type="MISSING_AUID", row_index=position, field="auid",
            ))
            continue
        auid = normalized.upper()
        if not validate_auid(auid):
            invalid_auid_rows += 1
            anomalies.append(ApplicationAnomaly(
                error_type="INVALID_AUID", row_index=position, field="auid", values=[normalized],
            ))
            continue
        rows_by_auid.setdefault(auid, []).append(position - 1)

    applications: list[ObjApplication] = []
    applications_with_conflicts: set[str] = set()
    null_counts: Counter[str] = Counter()
    conflict_counts: Counter[str] = Counter()
    for auid in sorted(rows_by_auid):
        row_indexes = rows_by_auid[auid]
        data: dict[str, Any] = {"auid": auid}
        for source_column, target_field in APPLICATION_COLUMN_MAPPING.items():
            value, conflicts = _canonical_value(frame.iloc[row_indexes][source_column].tolist())
            data[target_field] = value
            if value is None:
                null_counts[target_field] += 1
            if conflicts:
                applications_with_conflicts.add(auid)
                conflict_counts[target_field] += 1
                anomalies.append(ApplicationAnomaly(
                    error_type="APPLICATION_CONFLICT", auid=auid,
                    field=target_field, values=conflicts,
                ))
        applications.append(ObjApplication.model_validate(data))

    stats = {
        "input_rows": len(frame),
        "distinct_auid": len(rows_by_auid),
        "valid_applications": len(applications),
        "missing_auid_rows": missing_auid_rows,
        "invalid_auid_rows": invalid_auid_rows,
        "applications_with_conflicts": len(applications_with_conflicts),
        "conflict_count_by_field": dict(sorted(conflict_counts.items())),
        "null_count_by_field": {
            field: null_counts.get(field, 0) for field in APPLICATION_COLUMN_MAPPING.values()
        },
        "output_applications": len(applications),
    }
    return applications, anomalies, stats


def analyze_finding_coverage(
    findings_path: str | Path, applications: Iterable[ObjApplication]
) -> dict[str, Any]:
    finding_auids: set[str] = set()
    path = Path(findings_path)
    with path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, start=1):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid obj_finding JSON on line {line_no}: {exc.msg}") from exc
            application = payload.get("application") or {}
            value = normalize_string(application.get("auid"))
            if value is not None:
                finding_auids.add(value.upper())
    application_auids = {application.auid for application in applications}
    matched = finding_auids & application_auids
    unmatched = finding_auids - application_auids
    return {
        "distinct_auid_in_obj_findings": len(finding_auids),
        "distinct_auid_in_obj_applications": len(application_auids),
        "matched_auid": len(matched),
        "unmatched_auid": len(unmatched),
        "unmatched_auid_values": sorted(unmatched),
        "match_rate_percent": (
            round(100 * len(matched) / len(finding_auids), 4) if finding_auids else None
        ),
    }
