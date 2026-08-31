import json

import pandas as pd
import pytest

from scripts.build_obj_servers import main, write_outputs
from src.server_parser import parse_servers


def apm_row(auid="AP100", host="SERVER01", os_build="Windows 2022", environment="PROD", **extra):
    row = {
        "AUID": auid,
        "Host": host,
        "OS Build": os_build,
        "Environment": environment,
    }
    row.update(extra)
    return row


def write_findings(path, auids):
    payloads = [{"application": {"auid": auid}} for auid in auids]
    path.write_text(
        "".join(json.dumps(item) + "\n" for item in payloads), encoding="utf-8"
    )


def test_confirmed_mapping_and_no_sensitive_sources():
    frame = pd.DataFrame([apm_row(**{
        "CISO Top Critical Application": "Yes",
        "AppSec Criticality": "P4",
        "IS IV2 Server": "Yes",
    })])
    servers, relations, anomalies, _ = parse_servers(frame, {"AP100"})
    server = servers[0]
    assert server.hostname == "SERVER01"
    assert server.operating_system == "Windows 2022"
    assert server.environment == "PROD"
    assert server.sensitive is False
    assert server.authenticated_scan is True
    assert relations == [{"auid": "AP100", "hostname": "SERVER01"}]
    assert anomalies == []


def test_many_to_many_relations_and_server_consolidation():
    frame = pd.DataFrame([
        apm_row("AP100", "SERVER01"),
        apm_row("AP100", "SERVER02"),
        apm_row("AP200", "SERVER01"),
        apm_row("AP999", "OUTSIDE"),
        apm_row("AP100", "SERVER01"),
    ])
    servers, relations, _, stats = parse_servers(frame, {"AP100", "AP200"})
    assert [item.hostname for item in servers] == ["SERVER01", "SERVER02"]
    assert relations == [
        {"auid": "AP100", "hostname": "SERVER01"},
        {"auid": "AP100", "hostname": "SERVER02"},
        {"auid": "AP200", "hostname": "SERVER01"},
    ]
    assert stats["matching_apm_rows"] == 4
    assert stats["application_server_relations_detected"] == 3
    assert stats["distinct_applications_in_relations"] == 2
    assert stats["distinct_servers_in_relations"] == 2


def test_missing_host_is_reported_without_fallback():
    frame = pd.DataFrame([apm_row(host="", **{"SERVER TYPE": "Fallback host"})])
    servers, relations, anomalies, stats = parse_servers(frame, {"AP100"})
    assert servers == []
    assert relations == []
    assert anomalies[0].error_type == "MISSING_SERVER_HOSTNAME"
    assert stats["rows_without_host"] == 1


def test_empty_os_and_environment_have_no_fallbacks():
    frame = pd.DataFrame([apm_row(os_build=" ", environment="", **{
        "OS Host Container": "Fallback OS",
        "Technology": "Other OS",
    })])
    servers, _, _, stats = parse_servers(frame, {"AP100"})
    assert servers[0].operating_system is None
    assert servers[0].environment is None
    assert stats["servers_without_operating_system"] == 1
    assert stats["servers_without_environment"] == 1


@pytest.mark.parametrize(
    ("column", "field", "metric"),
    [
        ("OS Build", "operating_system", "operating_system_inconsistencies"),
        ("Environment", "environment", "environment_inconsistencies"),
    ],
)
def test_conflict_is_reported_without_arbitrary_selection(column, field, metric):
    changed = apm_row()
    changed[column] = "Different"
    servers, relations, anomalies, stats = parse_servers(
        pd.DataFrame([apm_row(), changed]), {"AP100"}
    )
    assert servers == []
    assert relations == []
    assert anomalies[0].hostname == "SERVER01"
    assert anomalies[0].field == field
    assert anomalies[0].distinct_value_count == 2
    assert stats[metric] == 1
    assert stats["server_inconsistencies"] == 1


@pytest.mark.parametrize("missing", ["AUID", "Host", "OS Build", "Environment"])
def test_missing_required_column_fails_explicitly(missing):
    frame = pd.DataFrame([apm_row()]).drop(columns=[missing])
    with pytest.raises(ValueError, match=missing):
        parse_servers(frame, {"AP100"})


def test_outputs_are_valid_and_inputs_are_unchanged(tmp_path):
    csv_path = tmp_path / "apm.csv"
    findings_path = tmp_path / "obj_findings.jsonl"
    applications_path = tmp_path / "obj_applications.jsonl"
    pd.DataFrame([apm_row(), apm_row("AP999", "OUTSIDE")]).to_csv(csv_path, index=False)
    write_findings(findings_path, [" ap100 "])
    applications_path.write_text('{"auid":"AP100"}\n', encoding="utf-8")
    findings_before = findings_path.read_bytes()
    applications_before = applications_path.read_bytes()

    servers_path, relations_path, anomalies_path, analysis_path, report = write_outputs(
        csv_path, findings_path, tmp_path / "output"
    )

    server = json.loads(servers_path.read_text(encoding="utf-8"))
    assert server["hostname"] == "SERVER01"
    assert server["operating_system"] == "Windows 2022"
    assert json.loads(relations_path.read_text(encoding="utf-8")) == {
        "auid": "AP100", "hostname": "SERVER01"
    }
    assert json.loads(anomalies_path.read_text(encoding="utf-8")) == []
    assert json.loads(analysis_path.read_text(encoding="utf-8"))["servers_generated"] == 1
    assert report["total_apm_rows"] == 2
    assert findings_path.read_bytes() == findings_before
    assert applications_path.read_bytes() == applications_before


def test_cli_requires_all_paths(tmp_path):
    csv_path = tmp_path / "apm.csv"
    pd.DataFrame([apm_row()]).to_csv(csv_path, index=False)
    with pytest.raises(SystemExit):
        main(["--input", str(csv_path)])

