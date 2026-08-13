import json
import subprocess
import sys
from pathlib import Path

from analyze_kri_mismatches import analyze
from main import write_outputs
from src.parser import parse_findings
from tests.conftest import synthetic_row


def test_server_kri_source_inconsistency_is_reported(csv_factory, tmp_path):
    rows = [
        synthetic_row(REM_KEY_ID="1", HOSTNAME="host-a", **{"KRI RAS 9": "true"}),
        synthetic_row(REM_KEY_ID="2", HOSTNAME="host-a", **{"KRI RAS 9": "false"}),
    ]
    raw_path = csv_factory(rows)
    findings, anomalies, stats = parse_findings(raw_path)
    assert not any(item.error_type == "KRI_MISMATCH" for item in anomalies)
    assert any(item.error_type == "KRI_SOURCE_SERVER_INCONSISTENT" for item in anomalies)
    assert stats["kri_ras9"]["server_source_control"]["source_inconsistencies"] == 1

    output = tmp_path / "output"
    write_outputs(findings, anomalies, stats, output, input_path=raw_path, run_timestamp="server")
    report = analyze(raw_path, output / "obj_findings.jsonl", output / "parser_anomalies.json", output)
    assert report["grain"] == "SERVER / DISTINCT_HOSTNAME"
    assert report["source_inconsistencies"] == 1
    assert report["warning_distribution"] == {"KRI_SOURCE_SERVER_INCONSISTENT": 1}
    assert (output / "PARSER-KRI_Mismatch_Analysis.md").stat().st_size > 0


def test_server_kri_analysis_cli_writes_reports(csv_factory, tmp_path):
    raw_path = csv_factory([
        synthetic_row(HOSTNAME="host-a", AGE="999", **{"KRI RAS 9": "false"})
    ])
    findings, anomalies, stats = parse_findings(raw_path)
    artifacts = tmp_path / "artifacts"
    write_outputs(findings, anomalies, stats, artifacts, input_path=raw_path, run_timestamp="cli")
    reports = tmp_path / "reports"
    script = Path(__file__).parents[1] / "analyze_kri_mismatches.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--raw", str(raw_path),
         "--findings", str(artifacts / "obj_findings.jsonl"),
         "--anomalies", str(artifacts / "parser_anomalies.json"),
         "--output-dir", str(reports)],
        cwd=script.parent, capture_output=True, text=True, check=False,
    )
    json_report = reports / "PARSER-KRI_Mismatch_Analysis.json"
    markdown_report = reports / "PARSER-KRI_Mismatch_Analysis.md"
    assert completed.returncode == 0, completed.stderr
    assert json_report.is_file() and markdown_report.stat().st_size > 0
    persisted = json.loads(json_report.read_text(encoding="utf-8"))
    assert persisted["server_level_mismatches"] == 1
    assert "Grain: SERVER / DISTINCT_HOSTNAME" in completed.stdout
