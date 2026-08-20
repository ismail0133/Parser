import json

from scripts.enrich_findings_with_applications import main
from src.enrichment.application_enricher import (
    enrich_finding_payload,
    enrich_findings_jsonl,
)


def finding(auid="AP100", **overrides):
    payload = {
        "application": {"auid": auid, "trigram": None, "name": None, "appsec": None},
        "business_line": None,
        "remediation_id": "REM-1",
    }
    payload.update(overrides)
    return payload


def application(auid="AP100", **overrides):
    payload = {
        "auid": auid,
        "code_app": "CODE",
        "trigram": "TRI",
        "application_name": "Application",
        "appsec": "P2",
        "business_line": "Business",
        "production_domain_manager": "Domain manager",
        "production_manager": "Manager",
    }
    payload.update(overrides)
    return payload


def write_jsonl(path, payloads):
    path.write_text(
        "".join(json.dumps(payload, ensure_ascii=False) + "\n" for payload in payloads),
        encoding="utf-8",
    )


def test_matched_finding_fills_only_supported_empty_fields():
    result, status, anomalies = enrich_finding_payload(
        finding(), {"AP100": [application()]},
    )
    assert status == "ENRICHED"
    assert result["application"] == {
        "auid": "AP100", "trigram": "TRI", "name": "Application", "appsec": "P2",
    }
    assert result["business_line"] == "Business"
    assert "code_app" not in result["application"]
    assert "production_manager" not in result["application"]
    assert anomalies == []


def test_missing_auid_is_preserved_and_reported_without_anomaly():
    source = finding(None)
    result, status, anomalies = enrich_finding_payload(source, {"AP100": [application()]})
    assert result == source
    assert status == "MISSING_AUID"
    assert anomalies == []


def test_missing_application_object_is_preserved_exactly():
    source = {"remediation_id": "REM-1", "business_line": None}
    result, status, anomalies = enrich_finding_payload(source, {"AP100": [application()]})
    assert result == source
    assert status == "MISSING_AUID"
    assert anomalies == []


def test_technically_empty_field_is_enriched():
    source = finding()
    source["application"]["name"] = "  "
    result, status, anomalies = enrich_finding_payload(source, {"AP100": [application()]})
    assert result["application"]["name"] == "Application"
    assert status == "ENRICHED"
    assert anomalies == []


def test_unmatched_auid_is_preserved_and_warned():
    source = finding("AP999")
    result, status, anomalies = enrich_finding_payload(source, {"AP100": [application()]})
    assert result == source
    assert status == "UNMATCHED_AUID"
    assert anomalies[0]["error_type"] == "UNMATCHED_AUID"


def test_equal_value_is_preserved_without_conflict():
    source = finding()
    source["application"]["name"] = "Application"
    result, status, anomalies = enrich_finding_payload(source, {"AP100": [application()]})
    assert result["application"]["name"] == "Application"
    assert status == "ENRICHED"
    assert anomalies == []


def test_different_value_is_preserved_and_conflict_reported():
    source = finding()
    source["application"]["name"] = "Finding name"
    result, status, anomalies = enrich_finding_payload(source, {"AP100": [application()]})
    assert result["application"]["name"] == "Finding name"
    assert status == "ENRICHED"
    assert anomalies[0]["error_type"] == "APPLICATION_ENRICHMENT_CONFLICT"
    assert anomalies[0]["field"] == "application.name"


def test_duplicate_application_auid_is_not_selected():
    source = finding()
    result, status, anomalies = enrich_finding_payload(
        source, {"AP100": [application(), application(application_name="Other")]},
    )
    assert result == source
    assert status == "APPLICATION_CONFLICT"
    assert anomalies == []


def test_complete_file_reuses_application_and_loses_no_finding(tmp_path):
    findings_path = tmp_path / "obj_findings.jsonl"
    applications_path = tmp_path / "obj_applications.jsonl"
    output_path = tmp_path / "obj_findings_enriched.jsonl"
    write_jsonl(findings_path, [finding(), finding(), finding(None), finding("AP999")])
    write_jsonl(applications_path, [application()])

    report = enrich_findings_jsonl(findings_path, applications_path, output_path)
    output = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert len(output) == 4
    assert output[0]["application"]["name"] == "Application"
    assert output[1]["application"]["name"] == "Application"
    assert report["total_findings"] == report["output_findings"] == 4
    assert report["enriched_findings"] == 2
    assert report["findings_without_auid"] == 1
    assert report["unmatched_findings"] == 1
    assert report["input_equals_output"] is True
    assert report["status"] == "SUCCESS"
    assert json.loads((tmp_path / "application_enrichment_report.json").read_text())["output_findings"] == 4


def test_duplicate_application_generates_warning_and_conflict_status(tmp_path):
    findings_path = tmp_path / "obj_findings.jsonl"
    applications_path = tmp_path / "obj_applications.jsonl"
    output_path = tmp_path / "obj_findings_enriched.jsonl"
    write_jsonl(findings_path, [finding()])
    write_jsonl(applications_path, [application(), application(application_name="Other")])
    report = enrich_findings_jsonl(findings_path, applications_path, output_path)
    anomalies = json.loads((tmp_path / "application_enrichment_anomalies.json").read_text())
    assert report["application_conflicts"] == 1
    assert anomalies[0]["error_type"] == "DUPLICATE_APPLICATION_AUID"


def test_cli_writes_valid_jsonl_and_reports_success(tmp_path):
    findings_path = tmp_path / "obj_findings.jsonl"
    applications_path = tmp_path / "obj_applications.jsonl"
    output_path = tmp_path / "obj_findings_enriched.jsonl"
    write_jsonl(findings_path, [finding()])
    write_jsonl(applications_path, [application()])
    assert main([
        "--findings", str(findings_path), "--applications", str(applications_path),
        "--output", str(output_path),
    ]) == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["application"]["auid"] == "AP100"
