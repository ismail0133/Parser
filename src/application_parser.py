"""Construction des applications à partir du CSV APM."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd

from src.cleaning.finding_cleaner import normalize_string
from src.models.application import ApplicationAnomaly, ObjApplication
from src.validation.finding_validator import validate_auid

APPLICATION_COLUMN_MAPPING = {
    "AUID": "auid",
    "Legacy APP ID": "trigram",
    "DAP Name": "name",
    "IT Cluster": "business_line",
    "AppSec Profile": "appsec",
    "CIB Vital DAP": "vital",
    "ITContinuityCriticality": "continuity_level",
    "App Manager": "application_manager",
    "Domain Manager": "domain_manager",
    "Production Manager": "production_manager",
    "Production Domain Manager": "production_domain_manager",
}
REQUIRED_APPLICATION_COLUMNS = ["AUID", "Legacy APP ID", "DAP Name"]
OPTIONAL_APPLICATION_COLUMNS = [
    column for column in APPLICATION_COLUMN_MAPPING
    if column not in REQUIRED_APPLICATION_COLUMNS
]


def extract_finding_auids(findings_path: str | Path) -> tuple[set[str], dict[str, int]]:
    """Extrait les AUID valides et distincts présents dans les findings."""
    path = Path(findings_path)
    if not path.is_file():
        raise FileNotFoundError(f"obj_findings file not found: {path}")

    valid_auids: set[str] = set()
    normalized_nonempty_auids: set[str] = set()
    missing_count = 0
    invalid_count = 0
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid obj_finding JSON on line {line_number}: {exc.msg}"
                ) from exc
            if not isinstance(payload, dict):
                raise ValueError(
                    f"Invalid obj_finding on line {line_number}: expected object"
                )
            application = payload.get("application")
            raw_auid = application.get("auid") if isinstance(application, dict) else None
            normalized = normalize_string(raw_auid)
            if normalized is None:
                missing_count += 1
                continue
            auid = normalized.upper()
            normalized_nonempty_auids.add(auid)
            if not validate_auid(auid):
                invalid_count += 1
                continue
            valid_auids.add(auid)

    return valid_auids, {
        "target_finding_auids": len(normalized_nonempty_auids),
        "valid_target_auids": len(valid_auids),
        "invalid_finding_auids": invalid_count,
        "missing_finding_auids": missing_count,
    }


def _normalized_series(series: pd.Series) -> pd.Series:
    return series.map(normalize_string)


def parse_applications(
    frame: pd.DataFrame, target_auids: set[str]
) -> tuple[list[ObjApplication], list[ApplicationAnomaly], dict[str, Any]]:
    """Construit une application cohérente par AUID du périmètre."""
    missing_columns = [
        column for column in REQUIRED_APPLICATION_COLUMNS if column not in frame.columns
    ]
    if missing_columns:
        raise ValueError(f"Missing required APM CSV columns: {missing_columns}")

    normalized_auids = _normalized_series(frame["AUID"]).str.upper()
    scoped = frame.loc[normalized_auids.isin(target_auids)].copy()
    scoped["AUID"] = normalized_auids.loc[scoped.index]

    applications: list[ObjApplication] = []
    anomalies: list[ApplicationAnomaly] = []
    inconsistent_auids: set[str] = set()
    conflict_counts: Counter[str] = Counter()
    found_auids = set(scoped["AUID"].tolist())

    for auid, rows in scoped.groupby("AUID", sort=True):
        data: dict[str, Any] = {"auid": auid}
        conflicts: list[tuple[str, int]] = []
        for source_column, target_field in APPLICATION_COLUMN_MAPPING.items():
            if target_field == "auid":
                continue
            values = (
                _normalized_series(rows[source_column]).dropna().unique()
                if source_column in rows.columns else []
            )
            if len(values) > 1:
                conflicts.append((target_field, len(values)))
            else:
                data[target_field] = values[0] if len(values) == 1 else None

        # On ne choisit aucune valeur si les données APM sont incohérentes.
        if conflicts:
            inconsistent_auids.add(auid)
            for field, distinct_value_count in conflicts:
                conflict_counts[field] += 1
                anomalies.append(
                    ApplicationAnomaly(
                        error_type="APPLICATION_CONFLICT",
                        auid=auid,
                        field=field,
                        distinct_value_count=distinct_value_count,
                    )
                )
            continue
        applications.append(ObjApplication.model_validate(data))

    missing_auids = target_auids - found_auids
    missing_optional_columns = [
        column for column in OPTIONAL_APPLICATION_COLUMNS if column not in frame.columns
    ]
    completeness = {
        f"{field}_populated": sum(
            getattr(application, field) is not None for application in applications
        )
        for field in (
            "business_line", "appsec", "vital", "continuity_level",
            "application_manager", "domain_manager", "production_manager",
            "production_domain_manager",
        )
    }
    stats = {
        "total_csv_rows": len(frame),
        "matching_apm_rows": len(scoped),
        "auids_found_in_apm": len(found_auids),
        "auids_missing_in_apm": len(missing_auids),
        "missing_auid_values": sorted(missing_auids),
        "applications_generated": len(applications),
        "applications_with_inconsistent_data": len(inconsistent_auids),
        "inconsistencies_by_field": dict(sorted(conflict_counts.items())),
        "missing_optional_columns": missing_optional_columns,
        **completeness,
        "coverage_rate": (
            round(100 * len(found_auids) / len(target_auids), 4)
            if target_auids else None
        ),
    }
    return applications, anomalies, stats
