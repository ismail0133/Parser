import json
from datetime import datetime

from main import write_outputs
from src.calculations.finding_calculations import calculate_kri_ras9
from src.parser import parse_findings
from src.reporting.finding_analysis import (
    build_analysis_report,
    generate_run_timestamp,
    render_analysis_markdown,
)
from tests.conftest import synthetic_row


def test_common_timestamp_and_official_artifact_names(csv_factory, tmp_path):
    findings, anomalies, stats = parse_findings(csv_factory())
    timestamp = generate_run_timestamp(datetime(2026, 8, 9, 16, 5, 0))
    assert timestamp == "20260809-160500"
    paths = write_outputs(
        findings, anomalies, stats, tmp_path,
        input_path="data/finding_list_fixed.csv", run_timestamp=timestamp,
    )
    assert paths["findings"].name == "PARSER-Findings-20260809-160500.json"
    assert paths["analysis_json"].name == "PARSER-Finding_Analysis-20260809-160500.json"
    assert paths["analysis_markdown"].name == "PARSER-Finding_Analysis-20260809-160500.md"
    assert all(timestamp in path.name for key, path in paths.items() if key in {"findings", "analysis_json", "analysis_markdown"})


def test_findings_json_and_markdown_exports(csv_factory, tmp_path):
    findings, anomalies, stats = parse_findings(csv_factory())
    paths = write_outputs(findings, anomalies, stats, tmp_path, run_timestamp="20260809-160500")
    finding_data = json.loads(paths["findings"].read_text(encoding="utf-8"))
    analysis = json.loads(paths["analysis_json"].read_text(encoding="utf-8"))
    markdown = paths["analysis_markdown"].read_text(encoding="utf-8")
    assert finding_data[0]["first_detection"] == "2026-05-01"
    assert analysis["data_quality"]["output_findings"] == len(finding_data)
    assert f"| Output Findings | {len(finding_data)} |" in markdown
    assert "# Parser Finding Analysis" in markdown


def test_analysis_statistics_and_distributions(csv_factory):
    rows = [
        synthetic_row(CVE="CVE-2026-1234", HOSTNAME="host-a", SEVERITY_LEVEL="Very High", ENVIRONMENT="PRODUCTION"),
        synthetic_row(REM_KEY_ID="2", CVE="CVE-2026-1234", HOSTNAME="host-a", SEVERITY_LEVEL="High", ENVIRONMENT="RECETTE", **{"Action Plan": "False positive"}),
        synthetic_row(REM_KEY_ID="3", CVE="CVE-2026-9999", HOSTNAME="host-b", SEVERITY_LEVEL="High", ENVIRONMENT="RECETTE", **{"Action Plan": "False positive to be confirmed"}),
    ]
    findings, anomalies, stats = parse_findings(csv_factory(rows))
    report = build_analysis_report(findings, anomalies, stats, timestamp="x", input_filename="f.csv", artifacts=[])
    assert report["findings"]["false_positives"] == 1
    assert report["findings"]["false_positives_to_confirm"] == 1
    assert report["findings"]["overdue_findings"] >= 1
    assert report["vulnerabilities"]["distinct_cve_count"] == 2
    assert report["vulnerabilities"]["top_cve"][0] == {"value": "CVE-2026-1234", "count": 2}
    assert {item["value"] for item in report["vulnerabilities"]["severity_distribution"]} == {"Very High", "High"}
    assert {item["value"] for item in report["vulnerabilities"]["environment_distribution"]} == {"PRODUCTION", "NON-PRODUCTION"}


def test_kri_computable_and_not_computable():
    computed = calculate_kri_ras9(
        hostname="host", server_sensitive=True, severity_level="Very High",
        overdue=True, false_positive=False,
    )
    assert computed == {"status": "COMPUTED", "result": True, "missing_fields": []}
    missing = calculate_kri_ras9(
        hostname=None, server_sensitive=True, severity_level=None,
        overdue=None, false_positive=False,
    )
    assert missing["status"] == "NOT_COMPUTABLE"
    assert set(missing["missing_fields"]) == {"hostname", "severity_level", "overdue"}


def test_kri_source_mismatch_and_open_points(csv_factory):
    row = synthetic_row(**{"KRI RAS 9": "false"})
    findings, anomalies, stats = parse_findings(csv_factory([row]))
    assert any(item.error_type == "KRI_MISMATCH" for item in anomalies)
    report = build_analysis_report(findings, anomalies, stats, timestamp="x", input_filename="f.csv", artifacts=[])
    assert report["kri_ras9"]["status"] == "COMPUTED"
    assert report["kri_ras9"]["qualifying_findings"] == 1
    fields = {item["field"] for item in report["open_points"]}
    assert {"unique_id", "remediation_id", "Colonne1", "remediation_strategy.strategy_type"} <= fields
    markdown = render_analysis_markdown(report)
    assert "OPEN POINTS / TO_VALIDATE" in markdown
