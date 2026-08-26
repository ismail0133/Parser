import argparse
import json
from datetime import datetime
from pathlib import Path

from src.models.parser_result import ParserResult
from src.parser import parse_findings
from src.reporting.finding_analysis import (
    OPEN_POINTS,
    build_analysis_report,
    generate_run_timestamp,
    render_analysis_markdown,
)


def _load_application_enrichment_report(output_dir: str | Path) -> dict | None:
    report_path = Path(output_dir) / "application_enrichment_report.json"
    if not report_path.is_file():
        return None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return report if isinstance(report, dict) else None


def _render_execution_summary(
    parser_result: ParserResult, enrichment_report: dict | None
) -> str:
    lines = [
        "## PARSER",
        "",
        f"Input rows       : {parser_result.input_rows}",
        f"Output findings  : {parser_result.output_findings}",
        f"Warnings         : {parser_result.warnings}",
        f"Errors           : {parser_result.errors}",
        f"Status           : {parser_result.status}",
        "",
        "## APPLICATION ENRICHMENT",
        "",
    ]
    if enrichment_report is None:
        lines.append("Status             : NOT_AVAILABLE")
        return "\n".join(lines)

    input_equals_output = enrichment_report.get("input_equals_output")
    integrity = (
        "YES" if input_equals_output is True
        else "NO" if input_equals_output is False
        else "NOT_AVAILABLE"
    )
    match_rate = enrichment_report.get("match_rate", "NOT_AVAILABLE")
    if isinstance(match_rate, (int, float)):
        match_rate = f"{match_rate}%"
    lines.extend([
        f"Status             : {enrichment_report.get('status', 'NOT_AVAILABLE')}",
        f"Findings with AUID : {enrichment_report.get('findings_with_auid', 'NOT_AVAILABLE')}",
        f"Without AUID       : {enrichment_report.get('findings_without_auid', 'NOT_AVAILABLE')}",
        f"Matched findings   : {enrichment_report.get('matched_findings', 'NOT_AVAILABLE')}",
        f"Enriched findings  : {enrichment_report.get('enriched_findings', 'NOT_AVAILABLE')}",
        f"Match rate         : {match_rate}",
        f"Conflicts          : {enrichment_report.get('application_conflicts', 'NOT_AVAILABLE')}",
        f"Field conflicts    : {enrichment_report.get('field_conflicts', 'NOT_AVAILABLE')}",
        f"Input = Output     : {integrity}",
    ])
    return "\n".join(lines)


def write_outputs(
    findings,
    anomalies,
    stats,
    output_dir: str | Path = "output",
    *,
    input_path: str | Path = "unknown.csv",
    run_timestamp: str | None = None,
) -> dict[str, Path]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    timestamp = run_timestamp or generate_run_timestamp()
    names = {
        "findings": f"PARSER-Findings-{timestamp}.json",
        "analysis_json": f"PARSER-Finding_Analysis-{timestamp}.json",
        "analysis_markdown": f"PARSER-Finding_Analysis-{timestamp}.md",
        "jsonl": "obj_findings.jsonl",
        "anomalies": "parser_anomalies.json",
        "report_alias": "parser_report.json",
        "parser_result": f"PARSER-Result-{timestamp}.json",
    }
    artifact_names = list(names.values())
    with (destination / names["findings"]).open("w", encoding="utf-8") as stream:
        json.dump([item.model_dump(mode="json") for item in findings], stream, ensure_ascii=False, indent=2)
    with (destination / "obj_findings.jsonl").open("w", encoding="utf-8") as stream:
        for finding in findings:
            stream.write(finding.model_dump_json() + "\n")
    with (destination / "parser_anomalies.json").open("w", encoding="utf-8") as stream:
        json.dump([item.model_dump(mode="json") for item in anomalies], stream, ensure_ascii=False, indent=2)
    analysis = build_analysis_report(
        findings, anomalies, stats,
        timestamp=timestamp,
        input_filename=str(input_path),
        artifacts=artifact_names,
    )
    with (destination / names["analysis_json"]).open("w", encoding="utf-8") as stream:
        json.dump(analysis, stream, ensure_ascii=False, indent=2)
    with (destination / names["analysis_markdown"]).open("w", encoding="utf-8") as stream:
        stream.write(render_analysis_markdown(analysis))
    with (destination / names["report_alias"]).open("w", encoding="utf-8") as stream:
        json.dump(analysis, stream, ensure_ascii=False, indent=2)
    status = (
        "FAILED" if stats["error_count"] > 0
        else "SUCCESS_WITH_WARNINGS" if stats["warning_count"] > 0
        else "SUCCESS"
    )
    parser_result = ParserResult(
        status=status,
        input_file=str(input_path),
        input_rows=stats["input_rows"],
        output_findings=stats["output_findings"],
        findings_artifact=names["findings"],
        errors=stats["error_count"],
        warnings=stats["warning_count"],
        infos=stats["info_count"],
        retry_count=stats["retry"]["retry_count"],
        max_attempts=stats["retry"]["max_attempts"],
        application_enrichment_status=stats["application_enrichment"]["status"],
        anomalies_artifact=names["anomalies"],
        analysis_report_artifact=names["analysis_json"],
        open_points=OPEN_POINTS,
        kri_ras9=stats["kri_ras9"],
        duration_seconds=stats["duration_seconds"],
    )
    with (destination / names["parser_result"]).open("w", encoding="utf-8") as stream:
        json.dump(parser_result.model_dump(mode="json"), stream, ensure_ascii=False, indent=2)
    return {key: destination / name for key, name in names.items()}


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description="Parse RAW Finding CSV into obj_finding JSONL")
    cli.add_argument("--input", required=True, help="Path to the confidential RAW Finding CSV")
    cli.add_argument("--limit", type=int, default=None, help="Read only the first N data rows")
    cli.add_argument("--output-dir", default="output", help="Output directory")
    args = cli.parse_args(argv)
    findings, anomalies, stats = parse_findings(args.input, limit=args.limit)
    artifacts = write_outputs(findings, anomalies, stats, args.output_dir, input_path=args.input)
    parser_result = ParserResult.model_validate_json(
        artifacts["parser_result"].read_text(encoding="utf-8")
    )
    enrichment_report = _load_application_enrichment_report(args.output_dir)
    print(_render_execution_summary(parser_result, enrichment_report))
    print(f"Duration         : {parser_result.duration_seconds:.3f}s")
    print(f"KRI percentage   : {stats['kri_ras9']['aggregate']['percentage']}")
    print(f"KRI target <30%  : {stats['kri_ras9']['aggregate']['business_target_met']}")
    print("Artifacts        :")
    for path in artifacts.values():
        print(f"  - {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
