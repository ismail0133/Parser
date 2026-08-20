from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from src.cleaning.finding_cleaner import normalize_string


ApplicationLookup = Mapping[str, Mapping[str, Any]] | Callable[[str], Mapping[str, Any] | None]


def enrich_with_application(
    finding: dict[str, Any], application_lookup: ApplicationLookup | None
) -> tuple[dict[str, Any], bool]:
    """Fill only missing application properties from an optional authoritative source."""
    if application_lookup is None:
        return finding, False
    auid = finding.get("application", {}).get("auid")
    if not auid:
        return finding, False
    application = (
        application_lookup(auid)
        if callable(application_lookup)
        else application_lookup.get(auid)
    )
    if not application:
        return finding, False
    target = finding.setdefault("application", {})
    for field in ("trigram", "name", "appsec", "vital", "cis"):
        if target.get(field) is None and application.get(field) is not None:
            target[field] = application[field]
    if finding.get("business_line") is None and application.get("business_line") is not None:
        finding["business_line"] = application["business_line"]
    return finding, True


# Only fields with an existing, unambiguous destination in Finding are eligible.
APPLICATION_FIELD_TARGETS = {
    "trigram": ("application", "trigram"),
    "application_name": ("application", "name"),
    "appsec": ("application", "appsec"),
    "business_line": (None, "business_line"),
}
UNMAPPED_APPLICATION_FIELDS = (
    "code_app", "production_domain_manager", "production_manager",
)


def normalize_matching_auid(value: Any) -> str | None:
    """Apply the project's existing technical normalization for AUID matching."""
    normalized = normalize_string(value)
    return normalized.upper() if normalized is not None else None


def _is_empty(value: Any) -> bool:
    return value is None or (isinstance(value, str) and normalize_string(value) is None)


def _read_jsonl(path: Path, object_name: str):
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid {object_name} JSON on line {line_number}: {exc.msg}"
                ) from exc
            if not isinstance(payload, dict):
                raise ValueError(f"Invalid {object_name} on line {line_number}: expected object")
            yield line_number, payload


def load_application_index(
    applications_path: str | Path,
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]], int]:
    """Index all application records without resolving duplicate AUIDs."""
    path = Path(applications_path)
    if not path.is_file():
        raise FileNotFoundError(f"obj_applications file not found: {path}")
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    total = 0
    for _, application in _read_jsonl(path, "obj_application"):
        total += 1
        auid = normalize_matching_auid(application.get("auid"))
        if auid is not None:
            index[auid].append(application)
    anomalies = [
        {
            "error_type": "DUPLICATE_APPLICATION_AUID",
            "severity": "WARNING",
            "auid": auid,
            "occurrences": len(applications),
            "message": "Multiple obj_application records have the same normalized AUID; no record was selected.",
        }
        for auid, applications in sorted(index.items()) if len(applications) > 1
    ]
    return dict(index), anomalies, total


def enrich_finding_payload(
    finding: Mapping[str, Any],
    application_index: Mapping[str, list[dict[str, Any]]],
    *,
    finding_line: int | None = None,
) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    """Enrich one finding conservatively and return its report-only status."""
    enriched = deepcopy(dict(finding))
    application_target = enriched.get("application")
    if application_target is None:
        return enriched, "MISSING_AUID", []
    if not isinstance(application_target, dict):
        raise ValueError("finding.application must be a JSON object")

    auid = normalize_matching_auid(application_target.get("auid"))
    if auid is None:
        return enriched, "MISSING_AUID", []
    matches = application_index.get(auid, [])
    if not matches:
        return enriched, "UNMATCHED_AUID", [{
            "error_type": "UNMATCHED_AUID", "severity": "WARNING",
            "finding_line": finding_line, "auid": auid,
            "message": "No obj_application matched the finding application AUID.",
        }]
    if len(matches) > 1:
        return enriched, "APPLICATION_CONFLICT", []

    source = matches[0]
    anomalies: list[dict[str, Any]] = []
    for source_field, (container, target_field) in APPLICATION_FIELD_TARGETS.items():
        application_value = source.get(source_field)
        if _is_empty(application_value):
            continue
        target = enriched if container is None else application_target
        finding_value = target.get(target_field)
        if _is_empty(finding_value):
            target[target_field] = application_value
        elif finding_value != application_value:
            anomalies.append({
                "error_type": "APPLICATION_ENRICHMENT_CONFLICT",
                "severity": "WARNING",
                "finding_line": finding_line,
                "auid": auid,
                "field": f"{container + '.' if container else ''}{target_field}",
                "finding_value": finding_value,
                "application_value": application_value,
                "message": "Finding value differs from obj_application; the finding value was preserved.",
            })
    return enriched, "ENRICHED", anomalies


def enrich_findings_jsonl(
    findings_path: str | Path,
    applications_path: str | Path,
    output_path: str | Path,
    *,
    report_path: str | Path | None = None,
    anomalies_path: str | Path | None = None,
) -> dict[str, Any]:
    """Enrich complete JSONL files and write output, report, and anomalies."""
    findings_file = Path(findings_path)
    applications_file = Path(applications_path)
    output_file = Path(output_path)
    if not findings_file.is_file():
        raise FileNotFoundError(f"obj_findings file not found: {findings_file}")
    if findings_file.resolve() == output_file.resolve():
        raise ValueError("Output path must differ from obj_findings input path")

    application_index, anomalies, total_applications = load_application_index(applications_file)
    report_file = Path(report_path) if report_path else output_file.parent / "application_enrichment_report.json"
    anomaly_file = Path(anomalies_path) if anomalies_path else output_file.parent / "application_enrichment_anomalies.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.parent.mkdir(parents=True, exist_ok=True)
    anomaly_file.parent.mkdir(parents=True, exist_ok=True)

    status_counts: Counter[str] = Counter()
    finding_auids: set[str] = set()
    matched_auids: set[str] = set()
    output_count = 0
    field_conflicts: Counter[str] = Counter()
    with output_file.open("w", encoding="utf-8") as output_stream:
        for line_number, finding in _read_jsonl(findings_file, "obj_finding"):
            application = finding.get("application") or {}
            if not isinstance(application, dict):
                raise ValueError(f"Invalid obj_finding on line {line_number}: application must be an object")
            auid = normalize_matching_auid(application.get("auid"))
            if auid is not None:
                finding_auids.add(auid)
            enriched, status, finding_anomalies = enrich_finding_payload(
                finding, application_index, finding_line=line_number,
            )
            if status == "ENRICHED":
                matched_auids.add(auid)  # type: ignore[arg-type]
            status_counts[status] += 1
            anomalies.extend(finding_anomalies)
            for anomaly in finding_anomalies:
                if anomaly["error_type"] == "APPLICATION_ENRICHMENT_CONFLICT":
                    field_conflicts[anomaly["field"]] += 1
            output_stream.write(json.dumps(enriched, ensure_ascii=False) + "\n")
            output_count += 1

    total_findings = sum(status_counts.values())
    findings_with_auid = total_findings - status_counts["MISSING_AUID"]
    unmatched_auids = finding_auids - matched_auids
    integrity_ok = total_findings == output_count
    report = {
        "status": "SUCCESS" if integrity_ok else "FAILED",
        "total_findings": total_findings,
        "total_applications": total_applications,
        "findings_with_auid": findings_with_auid,
        "findings_without_auid": status_counts["MISSING_AUID"],
        "matched_findings": status_counts["ENRICHED"],
        "unmatched_findings": status_counts["UNMATCHED_AUID"],
        "enriched_findings": status_counts["ENRICHED"],
        "application_conflicts": status_counts["APPLICATION_CONFLICT"],
        "field_conflicts": sum(field_conflicts.values()),
        "field_conflicts_by_field": dict(sorted(field_conflicts.items())),
        "match_rate": round(100 * status_counts["ENRICHED"] / findings_with_auid, 4) if findings_with_auid else None,
        "output_findings": output_count,
        "distinct_auid_findings": len(finding_auids),
        "distinct_auid_applications": len(application_index),
        "matched_distinct_auid": len(matched_auids),
        "unmatched_distinct_auid": len(unmatched_auids),
        "enrichment_status_counts": dict(sorted(status_counts.items())),
        "input_equals_output": integrity_ok,
        "unmapped_application_fields": list(UNMAPPED_APPLICATION_FIELDS),
        "artifacts": {
            "output": str(output_file.resolve()),
            "report": str(report_file.resolve()),
            "anomalies": str(anomaly_file.resolve()),
        },
    }
    anomaly_file.write_text(json.dumps(anomalies, ensure_ascii=False, indent=2), encoding="utf-8")
    report_file.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
