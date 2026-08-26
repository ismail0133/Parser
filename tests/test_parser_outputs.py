import json

from main import (
    _load_application_enrichment_report,
    _render_execution_summary,
    write_outputs,
)
from src.models.parser_result import ParserResult
from src.parser import parse_findings
from tests.conftest import synthetic_row


def test_obj_finding_creation_and_anomalies(csv_factory):
    path = csv_factory([synthetic_row()])
    findings, anomalies, stats = parse_findings(path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.application.auid == "AP10426"
    assert finding.server.os_name == "RHEL"
    assert finding.priority == 1
    assert finding.remediation_strategy.ownership_main is None
    assert stats["output_findings"] == 1
    assert any(item.error_type == "SLA_DEDUCED" for item in anomalies)


def test_anomaly_collection_for_invalid_values(csv_factory):
    row = synthetic_row(CVE="invalid", ENVIRONMENT="MARS", ABSOLUTE_FIRST_FOUND_DATE="", FIRST_FOUND_DATE="")
    _, anomalies, stats = parse_findings(csv_factory([row]))
    types = {item.error_type for item in anomalies}
    assert {"INVALID_CVE", "UNKNOWN_ENVIRONMENT", "MISSING_REQUIRED_VALUE"} <= types
    assert stats["parsed_with_errors"] == 1


def test_jsonl_output(csv_factory, tmp_path):
    findings, anomalies, stats = parse_findings(csv_factory())
    destination = tmp_path / "out"
    write_outputs(findings, anomalies, stats, destination)
    lines = (destination / "obj_findings.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["remediation_id"] == "1004-s00v19981544"
    assert (destination / "parser_anomalies.json").is_file()
    assert (destination / "parser_report.json").is_file()


def _reporting_parser_result(**overrides):
    values = {
        "status": "FAILED",
        "input_file": "input.csv",
        "input_rows": 17,
        "output_findings": 17,
        "findings_artifact": "findings.json",
        "errors": 4,
        "warnings": 6,
        "infos": 0,
        "retry_count": 0,
        "max_attempts": 3,
        "application_enrichment_status": "SKIPPED_NO_SOURCE",
        "anomalies_artifact": "anomalies.json",
        "analysis_report_artifact": "analysis.json",
        "open_points": [],
        "kri_ras9": {},
        "duration_seconds": 0.1,
    }
    values.update(overrides)
    return ParserResult(**values)


def test_main_summary_reads_real_enrichment_metrics_without_masking_parser_failure(tmp_path):
    report = {
        "status": "SUCCESS",
        "findings_with_auid": 13,
        "findings_without_auid": 4,
        "matched_findings": 12,
        "enriched_findings": 12,
        "match_rate": 92.3077,
        "application_conflicts": 2,
        "field_conflicts": 3,
        "input_equals_output": True,
    }
    (tmp_path / "application_enrichment_report.json").write_text(
        json.dumps(report), encoding="utf-8"
    )
    parser_result = _reporting_parser_result()
    before = parser_result.model_dump()

    summary = _render_execution_summary(
        parser_result, _load_application_enrichment_report(tmp_path)
    )

    assert "Status           : FAILED" in summary
    assert "Warnings         : 6" in summary
    assert "Errors           : 4" in summary
    assert "Status             : SUCCESS" in summary
    assert "Findings with AUID : 13" in summary
    assert "Without AUID       : 4" in summary
    assert "Matched findings   : 12" in summary
    assert "Enriched findings  : 12" in summary
    assert "Match rate         : 92.3077%" in summary
    assert "Conflicts          : 2" in summary
    assert "Field conflicts    : 3" in summary
    assert "Input = Output     : YES" in summary
    assert "SKIPPED_NO_SOURCE" not in summary
    assert parser_result.model_dump() == before


def test_main_summary_reports_enrichment_not_available(tmp_path):
    parser_result = _reporting_parser_result(warnings=8, errors=5)

    summary = _render_execution_summary(
        parser_result, _load_application_enrichment_report(tmp_path)
    )

    assert "Warnings         : 8" in summary
    assert "Errors           : 5" in summary
    assert "Status           : FAILED" in summary
    assert "Status             : NOT_AVAILABLE" in summary
    assert "SKIPPED_NO_SOURCE" not in summary
