"""Generate the KRI RAS 9 server-level control report without changing data."""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from src.calculations.finding_calculations import calculate_global_kri_ras9, parse_source_kri
from src.cleaning.finding_cleaner import clean_findings
from src.loaders.finding_loader import load_findings
from src.models.finding import Finding


SERVER_KRI_WARNING_TYPES = {
    "KRI_SERVER_MISMATCH",
    "KRI_SOURCE_SERVER_INCONSISTENT",
    "KRI_SOURCE_SERVER_UNINTERPRETABLE",
}


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def _load_anomalies(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    anomalies = payload.get("anomalies", payload) if isinstance(payload, dict) else payload
    if not isinstance(anomalies, list):
        raise RuntimeError("The anomalies artifact must be a JSON list or contain an 'anomalies' list")
    return anomalies


def analyze(raw_path: Path, findings_path: Path, anomalies_path: Path, output_dir: Path) -> dict[str, Any]:
    raw = clean_findings(load_findings(raw_path)).to_dict(orient="records")
    finding_dicts = _load_jsonl(findings_path)
    findings = [Finding.model_validate(item) for item in finding_dicts]
    anomalies = _load_anomalies(anomalies_path)
    if len(raw) != len(findings):
        raise RuntimeError(f"RAW/findings count mismatch: {len(raw)} != {len(findings)}")

    raw_by_hostname: dict[str, list[Any]] = defaultdict(list)
    for source_row, finding in zip(raw, findings):
        if finding.hostname:
            raw_by_hostname[finding.hostname].append(source_row.get("KRI RAS 9"))

    source_servers_checked = 0
    source_inconsistencies = 0
    source_uninterpretable = 0
    source_cases = []
    for hostname, values in raw_by_hostname.items():
        present = [value for value in values if value is not None]
        if not present:
            continue
        source_servers_checked += 1
        parsed = {parse_source_kri(value) for value in present}
        if None in parsed:
            category = "SOURCE_UNINTERPRETABLE"
            source_uninterpretable += 1
        elif len(parsed) > 1:
            category = "SOURCE_INCONSISTENT"
            source_inconsistencies += 1
        else:
            category = "SOURCE_CONSISTENT"
        source_cases.append({"hostname": hostname, "values_found": present, "category": category})

    warning_counts = Counter(
        item.get("error_type") for item in anomalies
        if item.get("error_type") in SERVER_KRI_WARNING_TYPES
    )
    aggregate = calculate_global_kri_ras9(findings)
    report = {
        "title": "KRI RAS 9 Analysis",
        "grain": aggregate["grain"],
        "eligible_servers": aggregate["eligible_sensitive_authenticated_servers"],
        "numerator_servers": aggregate["servers_with_overdue_critical_or_very_high"],
        "kri_percentage": aggregate["percentage"],
        "classification": aggregate["category"],
        "business_target": "< 30%",
        "business_target_met": aggregate["business_target_met"],
        "status": aggregate["status"],
        "source_kri_servers_checked": source_servers_checked,
        "source_inconsistencies": source_inconsistencies,
        "source_uninterpretable": source_uninterpretable,
        "server_level_mismatches": warning_counts["KRI_SERVER_MISMATCH"],
        "automatically_correctable": 0,
        "warnings": sum(warning_counts.values()),
        "warning_distribution": dict(warning_counts),
        "source_cases": source_cases,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "PARSER-KRI_Mismatch_Analysis.json"
    markdown_path = output_dir / "PARSER-KRI_Mismatch_Analysis.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    target = (
        "YES" if report["business_target_met"] is True
        else "NO" if report["business_target_met"] is False
        else "NOT_COMPUTABLE"
    )
    markdown = f"""# KRI RAS 9 Analysis

| Metric | Value |
|---|---:|
| Grain | {report['grain']} |
| Eligible servers | {report['eligible_servers']} |
| Numerator servers | {report['numerator_servers']} |
| KRI percentage | {report['kri_percentage'] if report['kri_percentage'] is not None else 'NOT_COMPUTABLE'} |
| Business target | < 30% |
| Business target met | {target} |
| Source KRI servers checked | {report['source_kri_servers_checked']} |
| Source inconsistencies | {report['source_inconsistencies']} |
| Source uninterpretable | {report['source_uninterpretable']} |
| Server-level mismatches | {report['server_level_mismatches']} |
| Automatically correctable | 0 |
| Warnings | {report['warnings']} |

## Warning distribution

```json
{json.dumps(report['warning_distribution'], ensure_ascii=False, indent=2)}
```
"""
    markdown_path.write_text(markdown, encoding="utf-8")
    report["json_report"] = str(json_path.resolve())
    report["markdown_report"] = str(markdown_path.resolve())
    return report


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--raw", default="data/finding_list_fixed.csv")
    cli.add_argument("--findings", default="output/obj_findings.jsonl")
    cli.add_argument("--anomalies", default="output/parser_anomalies.json")
    cli.add_argument("--output-dir", default="output")
    args = cli.parse_args()
    report = analyze(Path(args.raw), Path(args.findings), Path(args.anomalies), Path(args.output_dir))
    print(f"Grain: {report['grain']}")
    print(f"Eligible servers: {report['eligible_servers']}")
    print(f"Numerator servers: {report['numerator_servers']}")
    print(f"KRI percentage: {report['kri_percentage']}")
    print(f"Business target met: {report['business_target_met']}")
    print(f"Server-level mismatches: {report['server_level_mismatches']}")
    print(f"Source inconsistencies: {report['source_inconsistencies']}")
    print(f"JSON report: {report['json_report']}")
    print(f"Markdown report: {report['markdown_report']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
