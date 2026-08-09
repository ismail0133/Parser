import json

from main import write_outputs
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
    assert finding.remediation_strategy.ownership_main == "APS"
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
