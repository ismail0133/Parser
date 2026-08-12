from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from src.models.finding import Anomaly, Finding


OPEN_POINTS = [
    {"field": "unique_id", "status": "TO_VALIDATE", "reason": "Official generation formula not available"},
    {"field": "remediation_id", "status": "TO_VALIDATE", "reason": "Official fallback formula not available when REM_KEY_ID is missing"},
    {"field": "Proposed Owner", "status": "TO_VALIDATE", "reason": "Target property and business mapping rule are not confirmed"},
    {"field": "remediation_strategy.strategy_type", "status": "TO_VALIDATE", "reason": "Official derivation rules not available"},
    {"field": "KRI RAS 9 source comparison grain", "status": "TO_VALIDATE", "reason": "The CSV source value grain must be confirmed before replacing per-finding mismatch comparison"},
]


def generate_run_timestamp(now: datetime | None = None) -> str:
    return (now or datetime.now()).strftime("%Y%m%d-%H%M%S")


def _counter(values: Iterable[str | None], limit: int | None = None) -> list[dict[str, Any]]:
    items = Counter(value for value in values if value)
    ranked = items.most_common(limit)
    return [{"value": value, "count": count} for value, count in ranked]


def build_analysis_report(
    findings: list[Finding],
    anomalies: list[Anomaly],
    stats: dict[str, Any],
    *,
    timestamp: str,
    input_filename: str,
    artifacts: list[str],
) -> dict[str, Any]:
    false_positives = sum(item.false_positive for item in findings)
    false_positives_to_confirm = sum(item.false_positive_to_confirm for item in findings)
    ages = [item.age for item in findings if item.age is not None]
    anomaly_by_type = Counter(item.error_type for item in anomalies)
    anomaly_by_field = Counter(item.field for item in anomalies)
    errors = [item.model_dump(mode="json") for item in anomalies if item.severity == "ERROR"]
    return {
        "run_information": {
            "timestamp": timestamp,
            "input_filename": Path(input_filename).name,
            "input_rows": stats["input_rows"],
            "input_columns": stats["input_columns"],
            "duration_seconds": stats["duration_seconds"],
        },
        "data_quality": {
            "total_input_rows": stats["input_rows"],
            "successfully_parsed_findings": stats["parsed_successfully"],
            "findings_with_warnings": stats["parsed_with_warnings"],
            "findings_with_errors": stats["parsed_with_errors"],
            "output_findings": stats["output_findings"],
            "info_count": stats["info_count"],
            "warning_count": stats["warning_count"],
            "error_count": stats["error_count"],
        },
        "findings": {
            "total_findings": len(findings),
            "false_positives": false_positives,
            "false_positives_to_confirm": false_positives_to_confirm,
            "findings_to_remediate": len(findings) - false_positives,
            "overdue_findings": sum(item.overdue is True for item in findings),
            "average_age_days": round(mean(ages), 2) if ages else None,
        },
        "vulnerabilities": {
            "distinct_cve_count": len({item.cve for item in findings if item.cve}),
            "severity_distribution": _counter(item.severity_level for item in findings),
            "top_cve": _counter((item.cve for item in findings), 10),
            "top_hostnames": _counter((item.hostname for item in findings), 10),
            "environment_distribution": _counter((item.server.environment for item in findings)),
            "top_affected_products": _counter((item.affected_product for item in findings), 10),
        },
        "kri_ras9": stats["kri_ras9"],
        "application_enrichment": stats["application_enrichment"],
        "retry": stats["retry"],
        "anomalies": {
            "info": stats["info_count"],
            "warning": stats["warning_count"],
            "error": stats["error_count"],
            "by_error_type": [{"value": key, "count": count} for key, count in anomaly_by_type.most_common()],
            "by_field": [{"value": key, "count": count} for key, count in anomaly_by_field.most_common()],
            "error_sample": errors[:20],
            "all": [item.model_dump(mode="json") for item in anomalies],
        },
        "open_points": OPEN_POINTS,
        "artifacts": artifacts,
    }


def _metric_table(items: dict[str, Any]) -> str:
    rows = ["| Metric | Value |", "|---|---:|"]
    rows.extend(f"| {key.replace('_', ' ').title()} | {value if value is not None else 'N/A'} |" for key, value in items.items())
    return "\n".join(rows)


def _distribution_table(items: list[dict[str, Any]]) -> str:
    if not items:
        return "_No data available._"
    return "\n".join(["| Value | Count |", "|---|---:|"] + [f"| {item['value']} | {item['count']} |" for item in items])


def render_analysis_markdown(report: dict[str, Any]) -> str:
    kri = report["kri_ras9"]
    missing = ", ".join(kri.get("missing_fields", [])) or "None"
    open_rows = "\n".join(
        ["| Field | Status | Reason |", "|---|---|---|"]
        + [f"| {item['field']} | {item['status']} | {item['reason']} |" for item in report["open_points"]]
    )
    artifact_rows = "\n".join(f"- `{name}`" for name in report["artifacts"])
    return f"""# Parser Finding Analysis

## Run information

{_metric_table(report['run_information'])}

## Data Quality

{_metric_table(report['data_quality'])}

## Findings

{_metric_table(report['findings'])}

## Vulnerabilities

### Severity distribution

{_distribution_table(report['vulnerabilities']['severity_distribution'])}

### Top CVE

{_distribution_table(report['vulnerabilities']['top_cve'])}

### Top Hosts

{_distribution_table(report['vulnerabilities']['top_hostnames'])}

### Environment distribution

{_distribution_table(report['vulnerabilities']['environment_distribution'])}

### Top affected products

{_distribution_table(report['vulnerabilities']['top_affected_products'])}

## KRI RAS 9

| Metric | Value |
|---|---:|
| Status | {kri['status']} |
| Authenticated scan default | {kri['authenticated_scan_default']} |
| Computed findings | {kri['computed_findings']} |
| Not computable findings | {kri['not_computable_findings']} |
| Qualifying findings | {kri['qualifying_findings']} |
| Missing fields | {missing} |
| Aggregate status | {kri['aggregate']['status']} |
| Aggregate percentage | {kri['aggregate']['percentage'] if kri['aggregate']['percentage'] is not None else 'N/A'} |
| Aggregate numerator | {kri['aggregate']['servers_with_overdue_critical_or_very_high']} |
| Aggregate denominator | {kri['aggregate']['eligible_sensitive_authenticated_servers']} |

## Application enrichment

{_metric_table(report['application_enrichment'])}

## Retry

{_metric_table({'retry_count': report['retry']['retry_count'], 'max_attempts': report['retry']['max_attempts'], 'reason': report['retry']['reason']})}

## Errors / Warnings / Information

{_metric_table({'information': report['anomalies']['info'], 'warnings': report['anomalies']['warning'], 'errors': report['anomalies']['error']})}

### By error type

{_distribution_table(report['anomalies']['by_error_type'])}

### By field

{_distribution_table(report['anomalies']['by_field'])}

## OPEN POINTS / TO_VALIDATE

{open_rows}

## Generated Artifacts

{artifact_rows}
"""
