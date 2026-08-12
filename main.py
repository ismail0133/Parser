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
        duration_seconds=stats["duration_seconds"],
    )
    with (destination / names["parser_result"]).open("w", encoding="utf-8") as stream:
        json.dump(parser_result.model_dump(mode="json"), stream, ensure_ascii=False, indent=2)
    return {key: destination / name for key, name in names.items()}


def main() -> int:
    cli = argparse.ArgumentParser(description="Parse RAW Finding CSV into obj_finding JSONL")
    cli.add_argument("--input", required=True, help="Path to the confidential RAW Finding CSV")
    cli.add_argument("--limit", type=int, default=None, help="Read only the first N data rows")
    cli.add_argument("--output-dir", default="output", help="Output directory")
    args = cli.parse_args()
    findings, anomalies, stats = parse_findings(args.input, limit=args.limit)
    artifacts = write_outputs(findings, anomalies, stats, args.output_dir, input_path=args.input)
    status = (
        "FAILED" if stats["error_count"] > 0
        else "SUCCESS_WITH_WARNINGS" if stats["warning_count"] > 0
        else "SUCCESS"
    )
    print(f"Input rows       : {stats['input_rows']}")
    print(f"Parsed success   : {stats['parsed_successfully']}")
    print(f"Warnings         : {stats['warning_count']}")
    print(f"Errors           : {stats['error_count']}")
    print(f"Output findings  : {stats['output_findings']}")
    print(f"Duration         : {stats['duration_seconds']:.3f}s")
    print(f"Parser status    : {status}")
    print(f"App enrichment   : {stats['application_enrichment']['status']}")
    print("Artifacts        :")
    for path in artifacts.values():
        print(f"  - {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
