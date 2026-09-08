import json
from pathlib import Path

import pytest

from scripts.load_obj_findings_to_postgres import (
    JsonlInputError,
    main,
    prepare_inputs,
    prepare_server_inputs,
    read_jsonl,
)
from src.models.application import ObjApplication
from src.models.server import ObjServer
from tests.test_persistence_mapper import complete_finding


def write_jsonl(path: Path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def write_parser_artifacts(tmp_path: Path, *, output_findings: int):
    anomalies = tmp_path / "parser_anomalies.json"
    anomalies.write_text("[]", encoding="utf-8")
    result = tmp_path / "PARSER-Result.json"
    result.write_text(json.dumps({
        "component": "PARSER",
        "status": "SUCCESS",
        "input_file": "source.csv",
        "input_rows": output_findings,
        "output_findings": output_findings,
        "findings_artifact": "obj_findings.jsonl",
        "errors": 0,
        "warnings": 0,
        "infos": 0,
        "retry_count": 0,
        "max_attempts": 3,
        "application_enrichment_status": "SKIPPED_NO_SOURCE",
        "anomalies_artifact": anomalies.name,
        "analysis_report_artifact": "parser_analysis.json",
        "open_points": [],
        "kri_ras9": {},
        "duration_seconds": 0.1,
    }), encoding="utf-8")
    return result, anomalies


def canonical_application(auid="AP10426"):
    return {
        "auid": auid, "trigram": "ABC", "name": "App",
        "appsec": "P4", "business_line": "Retail", "vital": "GROUPE",
        "continuity_level": "HIGH", "application_manager": "Application Manager",
        "domain_manager": "Domain Manager",
        "production_domain_manager": "Domain", "production_manager": "Production",
    }


def test_valid_jsonl_and_dry_run(tmp_path, capsys):
    applications = write_jsonl(tmp_path / "applications.jsonl", [canonical_application()])
    findings = write_jsonl(tmp_path / "findings.jsonl", [complete_finding()])
    parser_result, parser_anomalies = write_parser_artifacts(tmp_path, output_findings=1)
    assert main([
        "--applications", str(applications),
        "--findings", str(findings),
        "--parser-result", str(parser_result),
        "--parser-anomalies", str(parser_anomalies),
        "--dry-run",
    ]) == 0
    output = capsys.readouterr().out
    assert "total_applications: 1" in output
    assert "total_findings: 1" in output
    assert "application_fk_resolved: 1" in output
    assert "input_equals_output: true" in output
    assert "status: READY" in output


def test_real_obj_application_jsonl_is_mapped_end_to_end(tmp_path):
    application = ObjApplication(
        auid="AP10426",
        trigram="ABC",
        name="App",
        business_line="Retail",
        appsec="P4",
        vital="GROUPE",
        continuity_level="HIGH",
        application_manager="Application Manager",
        domain_manager="Domain Manager",
        production_manager="Production Manager",
        production_domain_manager="Production Domain Manager",
    )
    applications = tmp_path / "applications.jsonl"
    applications.write_text(application.model_dump_json() + "\n", encoding="utf-8")
    findings = write_jsonl(tmp_path / "findings.jsonl", [complete_finding()])

    mapped_applications, _, stats, _ = prepare_inputs(applications, findings)

    assert stats.status == "READY"
    assert mapped_applications == [{
        "auid": "AP10426",
        "code_app": None,
        "trigram": "ABC",
        "application_name": "App",
        "appsec": "P4",
        "business_line": "Retail",
        "vital": "GROUPE",
        "continuity_level": "HIGH",
        "application_manager": "Application Manager",
        "domain_manager": "Domain Manager",
        "production_domain_manager": "Production Domain Manager",
        "production_manager": "Production Manager",
    }]


def test_obj_servers_jsonl_is_accepted_with_cli_servers_option(tmp_path, capsys):
    applications = write_jsonl(tmp_path / "applications.jsonl", [canonical_application()])
    findings = write_jsonl(tmp_path / "findings.jsonl", [complete_finding()])
    server = ObjServer(
        hostname="server01",
        operating_system="Red Hat Enterprise Linux 9.6",
        os_name="Red Hat Enterprise Linux",
        os_version="9.6",
        environment="PROD",
    )
    servers = tmp_path / "obj_servers.jsonl"
    servers.write_text(server.model_dump_json() + "\n", encoding="utf-8")
    relations = write_jsonl(
        tmp_path / "application_server_relations.jsonl",
        [{"auid": "AP10426", "hostname": "server01"}],
    )
    parser_result, parser_anomalies = write_parser_artifacts(tmp_path, output_findings=1)

    assert main([
        "--applications", str(applications),
        "--findings", str(findings),
        "--parser-result", str(parser_result),
        "--parser-anomalies", str(parser_anomalies),
        "--servers", str(servers),
        "--application-server-relations", str(relations),
        "--dry-run",
    ]) == 0

    output = capsys.readouterr().out
    assert "total_apm_servers: 1" in output
    assert "apm_servers_mapped: 1" in output
    assert "application_server_relations_mapped: 1" in output
    assert "status: READY" in output


def test_server_artifacts_preserve_os_and_many_to_many_relations(tmp_path):
    servers_path = write_jsonl(tmp_path / "obj_servers.jsonl", [
        ObjServer(
            hostname=" server01 ", operating_system="Linux 9",
            os_name="Linux", os_version="9", environment="PROD",
        ).model_dump(),
        ObjServer(
            hostname="server02", operating_system="Windows Server 2022",
            os_name="Windows Server", os_version="2022", environment="PROD",
        ).model_dump(),
    ])
    relations_path = write_jsonl(tmp_path / "application_server_relations.jsonl", [
        {"auid": "AP100", "hostname": "server01"},
        {"auid": "AP100", "hostname": "server02"},
        {"auid": "AP200", "hostname": "server01"},
    ])

    servers, relations, stats, messages = prepare_server_inputs(
        servers_path,
        relations_path,
        application_auids={"AP100", "AP200"},
    )

    assert servers[0]["hostname"] == "server01"
    assert servers[0]["operating_system"] == "Linux 9"
    assert servers[0]["environment_detail"] is None
    assert servers[0]["sensitive"] is None
    assert servers[0]["authenticated_scan"] is None
    assert relations == [
        {"auid": "AP100", "hostname": "server01"},
        {"auid": "AP100", "hostname": "server02"},
        {"auid": "AP200", "hostname": "server01"},
    ]
    assert stats.apm_servers_mapped == 2
    assert stats.application_server_relations_mapped == 3
    assert messages == []


@pytest.mark.parametrize("hostname", [None, "", "   "])
def test_invalid_apm_hostname_is_reported_and_never_mapped(tmp_path, hostname):
    servers_path = write_jsonl(tmp_path / "obj_servers.jsonl", [{"hostname": hostname}])

    servers, _, stats, messages = prepare_server_inputs(servers_path)

    assert servers == []
    assert stats.apm_servers_errors == 1
    assert stats.status == "FAILED"
    assert any("MISSING_SERVER_HOSTNAME" in message for message in messages)


def test_contradictory_apm_server_is_reported_as_server_conflict(tmp_path):
    servers_path = write_jsonl(tmp_path / "obj_servers.jsonl", [
        {"hostname": "server01", "operating_system": "Linux 8"},
        {"hostname": " server01 ", "operating_system": "Linux 9"},
    ])

    servers, _, stats, messages = prepare_server_inputs(servers_path)

    assert servers == []
    assert stats.server_conflicts == 1
    assert stats.status == "FAILED"
    assert messages == [
        "SERVER_CONFLICT hostname=server01 fields=operating_system"
    ]


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
        "vital", "continuity_level", "application_manager", "domain_manager",
        "production_domain_manager", "production_manager",
    ):
        assert f"{column} " in application_table
    assert "auid TEXT UNIQUE" in application_table
    finding_table = ddl.split("CREATE TABLE finding (", 1)[1].split(");", 1)[0]
    assert "application_id BIGINT REFERENCES application(application_id)" in finding_table
    assert "application_id BIGINT NOT NULL" not in finding_table
