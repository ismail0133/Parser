import json
from pathlib import Path

import pytest

from scripts.load_obj_findings_to_postgres import JsonlInputError, main, prepare_inputs, read_jsonl
from tests.test_persistence_mapper import complete_finding


def write_jsonl(path: Path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def canonical_application(auid="AP10426"):
    return {
        "auid": auid, "code_app": "CODE", "trigram": "ABC",
        "application_name": "App", "appsec": "P4", "business_line": "Retail",
        "production_domain_manager": "Domain", "production_manager": "Production",
    }


def test_valid_jsonl_and_dry_run(tmp_path, capsys):
    applications = write_jsonl(tmp_path / "applications.jsonl", [canonical_application()])
    findings = write_jsonl(tmp_path / "findings.jsonl", [complete_finding()])
    assert main(["--applications", str(applications), "--findings", str(findings), "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "total_applications: 1" in output
    assert "total_findings: 1" in output
    assert "application_fk_resolved: 1" in output
    assert "input_equals_output: true" in output
    assert "status: READY" in output


def test_invalid_json_line(tmp_path):
    path = tmp_path / "findings.jsonl"
    path.write_text("{bad}\n", encoding="utf-8")
    with pytest.raises(JsonlInputError, match="Line 1"):
        list(read_jsonl(path))


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        list(read_jsonl(Path("does-not-exist.jsonl")))


def test_zero_findings_is_ready_with_warning(tmp_path):
    applications = write_jsonl(tmp_path / "applications.jsonl", [canonical_application()])
    findings = write_jsonl(tmp_path / "findings.jsonl", [])
    mapped_apps, mapped_findings, stats, messages = prepare_inputs(applications, findings)
    assert len(mapped_apps) == 1
    assert mapped_findings == []
    assert stats.warnings == 1
    assert stats.input_equals_output is True
    assert messages


def test_same_cve_and_hostname_are_one_detected_shape(tmp_path):
    applications = write_jsonl(tmp_path / "applications.jsonl", [canonical_application()])
    rows = [complete_finding(remediation_id="R1"), complete_finding(remediation_id="R2")]
    findings = write_jsonl(tmp_path / "findings.jsonl", rows)
    _, mapped, stats, _ = prepare_inputs(applications, findings)
    assert len(mapped) == 2
    assert stats.servers_detected == 1
    assert stats.vulnerabilities_detected == 1
    assert stats.findings_mapped == 2
    assert stats.application_fk_resolved == 2


def test_missing_auid_keeps_finding_with_null_fk(tmp_path):
    applications = write_jsonl(tmp_path / "applications.jsonl", [canonical_application()])
    findings = write_jsonl(tmp_path / "findings.jsonl", [complete_finding(application={"auid": None})])
    _, mapped, stats, _ = prepare_inputs(applications, findings)
    assert len(mapped) == 1
    assert stats.findings_without_auid == 1
    assert stats.application_fk_unresolved == 0
    assert stats.input_equals_output is True


def test_present_but_unknown_auid_is_reported_without_losing_finding(tmp_path):
    applications = write_jsonl(tmp_path / "applications.jsonl", [canonical_application()])
    findings = write_jsonl(tmp_path / "findings.jsonl", [complete_finding(application={"auid": "AP999"})])
    _, mapped, stats, messages = prepare_inputs(applications, findings)
    assert len(mapped) == 1
    assert stats.application_fk_unresolved == 1
    assert stats.anomalies_detected == 1
    assert stats.status == "READY"
    assert any("UNRESOLVED_APPLICATION_AUID" in message for message in messages)


def test_duplicate_application_auid_fails_mapping(tmp_path):
    applications = write_jsonl(
        tmp_path / "applications.jsonl", [canonical_application(), canonical_application()]
    )
    findings = write_jsonl(tmp_path / "findings.jsonl", [complete_finding()])
    _, _, stats, _ = prepare_inputs(applications, findings)
    assert stats.applications_errors == 1
    assert stats.mapping_errors == 1
    assert stats.status == "FAILED"


def test_ddl_has_canonical_application_columns_and_nullable_finding_fk():
    ddl = Path("database/001_create_tables.sql").read_text(encoding="utf-8")
    application_table = ddl.split("CREATE TABLE application (", 1)[1].split(");", 1)[0]
    for column in (
        "auid", "code_app", "trigram", "application_name", "appsec", "business_line",
        "production_domain_manager", "production_manager",
    ):
        assert f"{column} " in application_table
    assert "auid TEXT UNIQUE" in application_table
    finding_table = ddl.split("CREATE TABLE finding (", 1)[1].split(");", 1)[0]
    assert "application_id BIGINT REFERENCES application(application_id)" in finding_table
    assert "application_id BIGINT NOT NULL" not in finding_table
