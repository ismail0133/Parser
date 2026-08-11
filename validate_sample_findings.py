"""Assisted business validation of RAW rows against generated obj_finding.

This script is read-only for input data. It selects up to 20 representative
cases and writes a JSON and Markdown validation report.
"""

from __future__ import annotations

import argparse
import json
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable

from src.calculations.finding_calculations import (
    calculate_age,
    calculate_overdue,
    calculate_server_sensitivity,
    calculate_sla,
)
from src.cleaning.finding_cleaner import clean_findings, normalize_string
from src.loaders.finding_loader import load_findings
from src.mapping.finding_mapper import normalize_priority
from src.parser import (
    normalize_as_of_date,
    normalize_environment,
    normalize_first_detection,
    normalize_last_detection,
    normalize_operating_system,
)
from src.validation.finding_validator import AUID_PATTERN


STATUS_ORDER = {"OK": 0, "TO_VALIDATE": 1, "WARNING": 2, "ERROR": 3}
RAW_FIELDS = [
    "Month", "REM_KEY_ID", "STATUS_REM", "HOSTNAME", "OPERATING_SYSTEM",
    "AFFECTED_PLATFORMS", "AUID", "ENVIRONMENT", "CODE_APP", "CVE", "title",
    "PRIORITY", "PRODUCT", "XTRACT_PATH", "ABSOLUTE_FIRST_FOUND_DATE",
    "FIRST_FOUND_DATE", "LAST_FOUND_DATE", "AGE", "SLA", "SEVERITY_LEVEL",
    "PROPOSED_ACTION", "Proposed Owner", "KRI RAS 9", "Action Plan", "ETA",
]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def _read_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _run_date(output_dir: Path) -> date:
    report = _read_json(output_dir / "parser_report.json", {})
    timestamp = report.get("run_information", {}).get("timestamp")
    if timestamp:
        try:
            return datetime.strptime(timestamp[:8], "%Y%m%d").date()
        except ValueError:
            pass
    return date.today()


def _get(obj: dict[str, Any], path: str) -> Any:
    value: Any = obj
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, date) else value


def _valid_auid(value: Any) -> str | None:
    text = normalize_string(value)
    return text.upper() if text and AUID_PATTERN.fullmatch(text) else None


def _check(field: str, raw_value: Any, obj_value: Any, expected: Any,
           status: str | None = None, comment: str = "") -> dict[str, Any]:
    expected = _iso(expected)
    actual_status = status or ("OK" if obj_value == expected else "ERROR")
    if actual_status == "ERROR" and not comment:
        comment = "obj_finding differs from the documented transformation"
    return {
        "field": field,
        "raw_value": raw_value,
        "obj_value": obj_value,
        "expected_value": expected,
        "status": actual_status,
        "comment": comment,
    }


def compare_case(row_index: int, raw: dict[str, Any], obj: dict[str, Any],
                 row_anomalies: list[dict[str, Any]], run_date: date) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    anomaly_types = {item.get("error_type") for item in row_anomalies}
    as_of, _ = normalize_as_of_date(raw.get("Month"), run_date)
    env_detail, env = normalize_environment(raw.get("ENVIRONMENT"))
    os_name, os_version = normalize_operating_system(
        raw.get("OPERATING_SYSTEM"), raw.get("AFFECTED_PLATFORMS")
    )
    first, _ = normalize_first_detection(
        raw.get("ABSOLUTE_FIRST_FOUND_DATE"), raw.get("FIRST_FOUND_DATE")
    )
    last = normalize_last_detection(raw.get("LAST_FOUND_DATE"))
    auid = _valid_auid(raw.get("AUID")) or _valid_auid(raw.get("CODE_APP"))
    action = normalize_string(raw.get("Action Plan"))
    folded_action = action.casefold() if action else ""
    false_positive = folded_action == "false positive"
    false_positive_to_confirm = "false positive to be confirmed" in folded_action

    direct = [
        ("as_of_date", "Month", as_of),
        ("remediation_id", "REM_KEY_ID", normalize_string(raw.get("REM_KEY_ID"))),
        ("hostname", "HOSTNAME", normalize_string(raw.get("HOSTNAME"))),
        ("server.os_name", "OPERATING_SYSTEM", os_name),
        ("server.os_version", "OPERATING_SYSTEM", os_version),
        ("server.environment_detail", "ENVIRONMENT", env_detail),
        ("server.environment", "ENVIRONMENT", env),
        ("application.auid", "AUID", auid),
        ("application.name", "Application Name", normalize_string(raw.get("Application Name"))),
        ("application.appsec", "AppSec Profile", normalize_string(raw.get("AppSec Profile"))),
        ("cve", "CVE", normalize_string(raw.get("CVE"))),
        ("cve_detail.title", "title", normalize_string(raw.get("title"))),
        ("priority", "PRIORITY", normalize_priority(raw.get("PRIORITY"))),
        ("affected_product", "PRODUCT", normalize_string(raw.get("PRODUCT"))),
        ("target", "XTRACT_PATH", normalize_string(raw.get("XTRACT_PATH"))),
        ("first_detection", "ABSOLUTE_FIRST_FOUND_DATE", first),
        ("last_detection", "LAST_FOUND_DATE", last),
        ("severity_level", "SEVERITY_LEVEL", normalize_string(raw.get("SEVERITY_LEVEL"))),
        ("proposed_action", "PROPOSED_ACTION", normalize_string(raw.get("PROPOSED_ACTION"))),
        ("remediation_strategy.description", "Action Plan", action),
        ("remediation_strategy.ownership_main", "XTRACT_PATH", None),
        ("false_positive", "Action Plan", false_positive),
        ("false_positive_to_confirm", "Action Plan", false_positive_to_confirm),
    ]
    for obj_path, raw_field, expected in direct:
        checks.append(_check(obj_path, raw.get(raw_field), _get(obj, obj_path), expected))

    checks.append(_check(
        "STATUS_REM", raw.get("STATUS_REM"), None, None, "OK",
        "Source column is documented as NOT_USED",
    ))
    checks.append(_check(
        "ownership", raw.get("Proposed Owner"), _get(obj, "ownership"), None,
        "TO_VALIDATE", "Proposed Owner target property and business rule are not confirmed",
    ))
    checks.append(_check(
        "remediation_strategy.strategy_type", raw.get("Action Plan"),
        _get(obj, "remediation_strategy.strategy_type"), None, "TO_VALIDATE",
        "Official strategy_type derivation rule is unavailable",
    ))

    age, _ = calculate_age(first, as_of, raw.get("AGE"), run_date)
    checks.append(_check(
        "age", raw.get("AGE"), obj.get("age"), age,
        comment="AGE_RECALCULATED" if "AGE_RECALCULATED" in anomaly_types else "",
    ))
    application = obj.get("application") or {}
    sla, _ = calculate_sla(
        raw.get("SLA"), application.get("appsec"), application.get("vital"),
        env, normalize_string(raw.get("SEVERITY_LEVEL")),
    )
    checks.append(_check(
        "sla", raw.get("SLA"), obj.get("sla"), sla,
        comment="SLA_DEDUCED" if "SLA_DEDUCED" in anomaly_types else "",
    ))
    checks.append(_check(
        "overdue", None, obj.get("overdue"), calculate_overdue(age, sla),
    ))
    expected_sensitive = calculate_server_sensitivity(
        application.get("appsec"), application.get("vital"), application.get("cis"), env_detail
    )
    checks.append(_check(
        "server.sensitive", None, _get(obj, "server.sensitive"), expected_sensitive,
    ))

    eta_source = normalize_string(raw.get("ETA"))
    expected_eta = None
    if eta_source and not false_positive:
        parsed_eta = normalize_last_detection(eta_source)
        expected_eta = parsed_eta
    checks.append(_check("eta", raw.get("ETA"), obj.get("eta"), expected_eta))

    kri_status = "WARNING" if "KRI_MISMATCH" in anomaly_types else "TO_VALIDATE"
    checks.append(_check(
        "KRI RAS 9", raw.get("KRI RAS 9"), None, None, kri_status,
        "Source KRI is a control value; calculated aggregate formula is not documented"
        if kri_status == "TO_VALIDATE" else "Source KRI differs from the calculated per-finding KRI",
    ))

    statuses = {item["status"] for item in checks}
    overall = "ERROR" if "ERROR" in statuses else "WARNING" if "WARNING" in statuses else "OK"
    return {
        "row_index": row_index,
        "remediation_id": obj.get("remediation_id"),
        "selection_reasons": [],
        "overall_status": overall,
        "has_to_validate": "TO_VALIDATE" in statuses,
        "raw": {field: raw.get(field) for field in RAW_FIELDS},
        "obj_finding": obj,
        "checks": checks,
        "parser_anomalies": row_anomalies,
    }


def _criterion_functions(anomalies_by_row: dict[int, list[dict[str, Any]]]) -> list[tuple[str, Callable]]:
    anomaly = lambda index, kind: any(
        item.get("error_type") == kind for item in anomalies_by_row.get(index, [])
    )
    return [
        ("first_rows", lambda i, r, o: i <= 3),
        *[(f"priority_{value}", lambda i, r, o, value=value: r.get("PRIORITY") == value)
          for value in ("PR1", "PR2", "PR3", "PR4")],
        ("environment_production", lambda i, r, o: r.get("ENVIRONMENT") == "PRODUCTION"),
        ("environment_integration", lambda i, r, o: r.get("ENVIRONMENT") == "INTEGRATION / PRE-RECETTE"),
        ("other_documented_environment", lambda i, r, o: r.get("ENVIRONMENT") not in {None, "", "PRODUCTION", "INTEGRATION / PRE-RECETTE"}),
        ("overdue_true", lambda i, r, o: o.get("overdue") is True),
        ("overdue_false", lambda i, r, o: o.get("overdue") is False),
        ("false_positive", lambda i, r, o: o.get("false_positive") is True),
        ("false_positive_to_confirm", lambda i, r, o: o.get("false_positive_to_confirm") is True),
        ("eta_present", lambda i, r, o: normalize_string(r.get("ETA")) is not None),
        ("eta_absent", lambda i, r, o: normalize_string(r.get("ETA")) is None),
        ("sla_provided", lambda i, r, o: normalize_string(r.get("SLA")) is not None),
        ("sla_deduced", lambda i, r, o: anomaly(i, "SLA_DEDUCED")),
        ("age_preserved", lambda i, r, o: not anomaly(i, "AGE_RECALCULATED")),
        ("age_recalculated", lambda i, r, o: anomaly(i, "AGE_RECALCULATED")),
        ("path_apps", lambda i, r, o: (normalize_string(r.get("XTRACT_PATH")) or "").casefold().startswith("/apps/")),
        ("path_other", lambda i, r, o: bool(normalize_string(r.get("XTRACT_PATH"))) and not (normalize_string(r.get("XTRACT_PATH")) or "").casefold().startswith("/apps/")),
        ("kri_mismatch", lambda i, r, o: anomaly(i, "KRI_MISMATCH")),
    ]


def select_sample(raw_rows: list[dict[str, Any]], objects: list[dict[str, Any]],
                  anomalies_by_row: dict[int, list[dict[str, Any]]], size: int = 20
                  ) -> tuple[list[tuple[int, list[str]]], list[str]]:
    criteria = _criterion_functions(anomalies_by_row)
    selected: dict[int, list[str]] = {}
    unavailable: list[str] = []
    for label, predicate in criteria:
        candidates = [index for index, (raw, obj) in enumerate(zip(raw_rows, objects), start=1)
                      if predicate(index, raw, obj)]
        if not candidates:
            unavailable.append(label)
            continue
        existing = next((index for index in candidates if index in selected), None)
        if existing is not None:
            selected[existing].append(label)
        elif len(selected) < size:
            selected[candidates[0]] = [label]
    if len(selected) < size and raw_rows:
        step = max(1, len(raw_rows) // max(1, size - len(selected)))
        for index in range(1, len(raw_rows) + 1, step):
            if index not in selected:
                selected[index] = ["portfolio_spread"]
            if len(selected) == size:
                break
    return sorted(selected.items())[:size], unavailable


def _markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    selection_rows = "\n".join(
        f"| {case['row_index']} | {case['remediation_id'] or ''} | {', '.join(case['selection_reasons'])} | {case['overall_status']} |"
        for case in report["cases"]
    )
    error_rows = []
    for case in report["cases"]:
        for check in case["checks"]:
            if check["status"] in {"ERROR", "WARNING"}:
                error_rows.append(
                    f"| {case['row_index']} | {check['field']} | {check['status']} | {check['comment']} |"
                )
    details = "\n".join(error_rows) or "| — | — | — | No errors or warnings |"
    unavailable = "\n".join(f"- `{item}`" for item in report["unavailable_criteria"]) or "- None"
    return f"""# Parser Sample Validation

## Summary

| Metric | Value |
|---|---:|
| Sample size | {summary['sample_size']} |
| Fully valid | {summary['fully_valid']} |
| With warnings | {summary['with_warnings']} |
| Errors | {summary['errors']} |
| TO_VALIDATE | {summary['to_validate']} |

## Sample selection

| RAW row | Remediation ID | Selection reasons | Status |
|---:|---|---|---|
{selection_rows}

## Errors and warnings

| RAW row | Field | Status | Comment |
|---:|---|---|---|
{details}

## Unavailable requested criteria

{unavailable}

Full RAW values, obj_finding values and field-by-field checks are available in `PARSER-Sample_Validation.json`.
"""


def validate_sample(raw_path: Path, findings_path: Path, output_dir: Path,
                    sample_size: int = 20) -> dict[str, Any]:
    raw_frame = clean_findings(load_findings(raw_path))
    raw_rows = raw_frame.to_dict(orient="records")
    objects = _read_jsonl(findings_path)
    if len(raw_rows) != len(objects):
        raise RuntimeError(
            "RAW and obj_finding counts differ; ordinal correspondence cannot be guaranteed: "
            f"raw={len(raw_rows)}, findings={len(objects)}"
        )
    anomalies = _read_json(output_dir / "parser_anomalies.json", [])
    anomalies_by_row: dict[int, list[dict[str, Any]]] = {}
    for item in anomalies:
        anomalies_by_row.setdefault(int(item["row_index"]), []).append(item)
    selected, unavailable = select_sample(raw_rows, objects, anomalies_by_row, sample_size)
    run_date = _run_date(output_dir)
    cases = []
    for row_index, reasons in selected:
        case = compare_case(
            row_index, raw_rows[row_index - 1], objects[row_index - 1],
            anomalies_by_row.get(row_index, []), run_date,
        )
        case["selection_reasons"] = reasons
        cases.append(case)
    summary = {
        "sample_size": len(cases),
        "fully_valid": sum(case["overall_status"] == "OK" for case in cases),
        "with_warnings": sum(case["overall_status"] == "WARNING" for case in cases),
        "errors": sum(case["overall_status"] == "ERROR" for case in cases),
        "to_validate": sum(case["has_to_validate"] for case in cases),
    }
    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "raw_file": str(raw_path),
        "findings_file": str(findings_path),
        "summary": summary,
        "unavailable_criteria": unavailable,
        "cases": cases,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "PARSER-Sample_Validation.json").open("w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    with (output_dir / "PARSER-Sample_Validation.md").open("w", encoding="utf-8") as stream:
        stream.write(_markdown(report))
    return report


def main() -> int:
    cli = argparse.ArgumentParser(description="Validate a representative RAW/obj_finding sample")
    cli.add_argument("--raw", default="data/finding_list_fixed.csv")
    cli.add_argument("--findings", default="output/obj_findings.jsonl")
    cli.add_argument("--output-dir", default="output")
    cli.add_argument("--sample-size", type=int, default=20)
    args = cli.parse_args()
    report = validate_sample(
        Path(args.raw), Path(args.findings), Path(args.output_dir), args.sample_size
    )
    summary = report["summary"]
    print("Parser Sample Validation")
    print(f"Sample size    : {summary['sample_size']}")
    print(f"Fully valid   : {summary['fully_valid']}")
    print(f"Warnings      : {summary['with_warnings']}")
    print(f"Errors        : {summary['errors']}")
    print(f"TO_VALIDATE   : {summary['to_validate']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
