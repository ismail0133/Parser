import json

from analyze_kri_mismatches import _extract_kri_mismatches, analyze
from main import write_outputs
from src.parser import parse_findings
from tests.conftest import synthetic_row


def test_kri_aggregate_uses_distinct_sensitive_hosts(csv_factory):
    rows = [
        synthetic_row(REM_KEY_ID="1", HOSTNAME="host-a", **{"KRI RAS 9": "false"}),
        synthetic_row(REM_KEY_ID="2", HOSTNAME="host-a", CVE="CVE-2026-9999"),
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
    raw_path = csv_factory([synthetic_row(**{"KRI RAS 9": "false"})])
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
