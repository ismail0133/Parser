"""Generate a technical analysis of KRI_MISMATCH anomalies without changing data."""

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from src.calculations.finding_calculations import calculate_kri_ras9, parse_source_kri
from src.cleaning.finding_cleaner import clean_findings
from src.loaders.finding_loader import load_findings


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def _classify(source: bool | None, calculated: dict[str, Any]) -> tuple[str, str]:
    if calculated["status"] != "COMPUTED":
        return "MISSING_REQUIRED_CONTEXT", "The individual KRI condition is not computable"
    if source is None:
        return "DATA_NORMALIZATION_ISSUE", "The source KRI is not an unambiguous boolean value"
    return (
        "GRAIN_MISMATCH",
        "The source KRI may represent an aggregate/server-level value while the current warning compares it to an individual finding condition",
    )


def analyze(raw_path: Path, findings_path: Path, anomalies_path: Path, output_dir: Path) -> dict[str, Any]:
    raw = clean_findings(load_findings(raw_path)).to_dict(orient="records")
    findings = _load_jsonl(findings_path)
    anomalies = json.loads(anomalies_path.read_text(encoding="utf-8"))
    if len(raw) != len(findings):
        raise RuntimeError(f"RAW/findings count mismatch: {len(raw)} != {len(findings)}")
    mismatch_rows = sorted({int(item["row_index"]) for item in anomalies if item["error_type"] == "KRI_MISMATCH"})
    cases = []
    for row_index in mismatch_rows:
        source_row = raw[row_index - 1]
        finding = findings[row_index - 1]
        server = finding.get("server") or {}
        calculated = calculate_kri_ras9(
            hostname=finding.get("hostname"),
            server_sensitive=bool(server.get("sensitive")),
            severity_level=finding.get("severity_level"),
            overdue=finding.get("overdue"),
            false_positive=bool(finding.get("false_positive")),
        )
        source = parse_source_kri(source_row.get("KRI RAS 9"))
        category, reason = _classify(source, calculated)
        cases.append({
            "row_index": row_index,
            "remediation_id": finding.get("remediation_id"),
            "hostname": finding.get("hostname"),
            "cve": finding.get("cve"),
            "severity": finding.get("severity_level"),
            "environment": server.get("environment"),
            "server_sensitive": server.get("sensitive"),
            "authenticated_scan": True,
            "age": finding.get("age"),
            "sla": finding.get("sla"),
            "overdue": finding.get("overdue"),
            "false_positive": finding.get("false_positive"),
            "source_kri": source,
            "source_kri_raw": source_row.get("KRI RAS 9"),
            "calculated_kri": calculated.get("result"),
            "calculation_status": calculated.get("status"),
            "category": category,
            "reason": reason,
        })
    distribution = Counter(item["category"] for item in cases)
    report = {
        "total_kri_mismatches": len(cases),
        "distribution_by_cause": dict(distribution),
        "actually_correctable": sum(item["category"] in {"CALCULATION_RULE_ISSUE", "DATA_NORMALIZATION_ISSUE"} for item in cases),
        "legitimately_kept_as_warning": sum(item["category"] in {"SOURCE_VALUE_DIFFERS", "GRAIN_MISMATCH"} for item in cases),
        "requiring_business_validation": sum(item["category"] in {"GRAIN_MISMATCH", "BUSINESS_RULE_TO_VALIDATE"} for item in cases),
        "cases": cases,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "PARSER-KRI_Mismatch_Analysis.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    rows = "\n".join(
        f"| {item['row_index']} | {item['remediation_id'] or ''} | {item['hostname'] or ''} | {item['source_kri']} | {item['calculated_kri']} | {item['category']} |"
        for item in cases
    ) or "| — | — | — | — | — | No KRI mismatch |"
    markdown = f"""# Parser KRI Mismatch Analysis

## Summary

| Metric | Value |
|---|---:|
| Total KRI mismatches | {report['total_kri_mismatches']} |
| Actually correctable | {report['actually_correctable']} |
| Legitimately kept as warning | {report['legitimately_kept_as_warning']} |
| Requiring business validation | {report['requiring_business_validation']} |

## Distribution by cause

```json
{json.dumps(report['distribution_by_cause'], ensure_ascii=False, indent=2)}
```

## Cases

| RAW row | Remediation ID | Hostname | Source KRI | Calculated finding KRI | Category |
|---:|---|---|---:|---:|---|
{rows}
"""
    (output_dir / "PARSER-KRI_Mismatch_Analysis.md").write_text(markdown, encoding="utf-8")
    return report


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--raw", default="data/finding_list_fixed.csv")
    cli.add_argument("--findings", default="output/obj_findings.jsonl")
    cli.add_argument("--anomalies", default="output/parser_anomalies.json")
    cli.add_argument("--output-dir", default="output")
    args = cli.parse_args()
    report = analyze(Path(args.raw), Path(args.findings), Path(args.anomalies), Path(args.output_dir))
    print(f"Total KRI mismatches              : {report['total_kri_mismatches']}")
    print(f"Répartition par cause             : {report['distribution_by_cause']}")
    print(f"Nombre réellement corrigeables    : {report['actually_correctable']}")
    print(f"Nombre conservés en warning       : {report['legitimately_kept_as_warning']}")
    print(f"Nombre nécessitant validation     : {report['requiring_business_validation']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
