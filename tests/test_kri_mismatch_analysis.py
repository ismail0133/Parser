import json
import subprocess
import sys
from pathlib import Path

from analyze_kri_mismatches import _extract_kri_mismatches, analyze
from main import write_outputs
from src.parser import parse_findings
from tests.conftest import synthetic_row


def test_kri_aggregate_uses_distinct_sensitive_hosts(csv_factory):
    rows = [
        synthetic_row(REM_KEY_ID="1", HOSTNAME="host-a", AGE="999", **{"KRI RAS 9": "false"}),
        synthetic_row(REM_KEY_ID="2", HOSTNAME="host-a", CVE="CVE-2026-9999", AGE="999"),
        synthetic_row(REM_KEY_ID="3", HOSTNAME="host-b", **{"Action Plan": "False positive"}),
    ]
    _, _, stats = parse_findings(csv_factory(rows))
    aggregate = stats["kri_ras9"]["aggregate"]
    assert aggregate["grain"] == "DISTINCT_HOSTNAME"
    assert aggregate["eligible_sensitive_authenticated_servers"] == 2
    assert aggregate["servers_with_overdue_critical_or_very_high"] == 1
    assert aggregate["percentage"] == 50.0
    assert aggregate["category"] == "UNSATISFACTORY"


def test_kri_mismatch_analysis_artifacts(csv_factory, tmp_path):
    raw_path = csv_factory([synthetic_row(AGE="999", **{"KRI RAS 9": "false"})])
    findings, anomalies, stats = parse_findings(raw_path)
    output = tmp_path / "output"
    write_outputs(findings, anomalies, stats, output, input_path=raw_path, run_timestamp="x")
    report = analyze(raw_path, output / "obj_findings.jsonl", output / "parser_anomalies.json", output)
    assert report["total_kri_mismatches"] == 1
    assert report["distribution_by_cause"] == {"GRAIN_MISMATCH": 1}
    assert (output / "PARSER-KRI_Mismatch_Analysis.md").is_file()
    persisted = json.loads((output / "PARSER-KRI_Mismatch_Analysis.json").read_text(encoding="utf-8"))
    assert persisted["cases"][0]["authenticated_scan"] is True


def test_extracts_all_mismatches_from_real_anomaly_schema():
    anomalies = [
        {
            "row_index": index,
            "rem_key_id": f"rem-{index}",
            "field": "KRI RAS 9",
            "value": "false",
            "severity": "WARNING",
            "error_type": "KRI_MISMATCH",
            "message": "Source KRI differs from calculated KRI",
            "classification": "WARNING",
        }
        for index in range(1, 51)
    ]
    mismatches, key = _extract_kri_mismatches(anomalies)
    assert key == "error_type"
    assert len(mismatches) == 50


def test_kri_mismatch_cli_writes_non_empty_reports(csv_factory, tmp_path):
    raw_path = csv_factory([synthetic_row(AGE="999", **{"KRI RAS 9": "false"})])
    findings, anomalies, stats = parse_findings(raw_path)
    artifacts_dir = tmp_path / "artifacts"
    write_outputs(findings, anomalies, stats, artifacts_dir, input_path=raw_path, run_timestamp="cli")
    reports_dir = tmp_path / "reports"
    script = Path(__file__).parents[1] / "analyze_kri_mismatches.py"

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--raw", str(raw_path),
            "--findings", str(artifacts_dir / "obj_findings.jsonl"),
            "--anomalies", str(artifacts_dir / "parser_anomalies.json"),
            "--output-dir", str(reports_dir),
        ],
        cwd=script.parent,
        capture_output=True,
        text=True,
        check=False,
    )

    json_report = reports_dir / "PARSER-KRI_Mismatch_Analysis.json"
    markdown_report = reports_dir / "PARSER-KRI_Mismatch_Analysis.md"
    assert completed.returncode == 0, completed.stderr
    assert json_report.is_file()
    assert markdown_report.is_file()
    assert markdown_report.stat().st_size > 0
    assert json.loads(json_report.read_text(encoding="utf-8"))["total_kri_mismatches"] == 1
    assert "Total KRI mismatches: 1" in completed.stdout
    assert "Identification key: error_type" in completed.stdout
    assert f"JSON report: {json_report.resolve()}" in completed.stdout
    assert f"Markdown report: {markdown_report.resolve()}" in completed.stdout
