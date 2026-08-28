import json

import pandas as pd
import pytest

from scripts.build_obj_applications import main, write_outputs
from src.application_parser import extract_finding_auids, parse_applications


def apm_row(auid="AP100", trigram="ABC", name="Payment App", **extra):
    row = {"AUID": auid, "Legacy APP ID": trigram, "DAP Name": name}
    row.update(extra)
    return row


def write_findings(path, auids):
    payloads = [
        {"application": {"auid": auid}, "unchanged": index}
        for index, auid in enumerate(auids)
    ]
    path.write_text("".join(json.dumps(item) + "\n" for item in payloads), encoding="utf-8")
    return payloads


def test_official_mapping_and_no_fallbacks():
    frame = pd.DataFrame([apm_row(**{"Application Name": "Wrong", "APM APP ID": "AP999"})])
    applications, anomalies, _ = parse_applications(frame, {"AP100"})
    assert applications[0].model_dump() == {
        "auid": "AP100", "trigram": "ABC", "name": "Payment App",
    }
    assert anomalies == []


def test_filters_to_distinct_valid_finding_auids(tmp_path):
    findings = tmp_path / "obj_findings.jsonl"
    write_findings(findings, [" ap100 ", "AP100", "", None, "BAD"])
    targets, stats = extract_finding_auids(findings)
    applications, _, app_stats = parse_applications(
        pd.DataFrame([apm_row(), apm_row("AP200", "XYZ", "Outside")]), targets,
    )
    assert targets == {"AP100"}
    assert [item.auid for item in applications] == ["AP100"]
    assert stats == {
        "target_finding_auids": 2,
        "valid_target_auids": 1,
        "invalid_finding_auids": 1,
        "missing_finding_auids": 2,
    }
    assert app_stats["matching_apm_rows"] == 1


def test_missing_target_is_reported():
    applications, _, stats = parse_applications(pd.DataFrame([apm_row()]), {"AP100", "AP200"})
    assert len(applications) == 1
    assert stats["auids_missing_in_apm"] == 1
    assert stats["missing_auid_values"] == ["AP200"]
    assert stats["coverage_rate"] == 50.0


def test_identical_repeated_rows_make_one_application():
    applications, anomalies, _ = parse_applications(
        pd.DataFrame([apm_row(Host="SERVER01"), apm_row(Host="SERVER02")]), {"AP100"},
    )
    assert len(applications) == 1
    assert anomalies == []


@pytest.mark.parametrize(
    ("changed_column", "expected_field"),
    [("Legacy APP ID", "trigram"), ("DAP Name", "name")],
)
def test_inconsistent_application_data_is_reported_and_not_generated(changed_column, expected_field):
    second = apm_row()
    second[changed_column] = "Different"
    applications, anomalies, stats = parse_applications(
        pd.DataFrame([apm_row(), second]), {"AP100"},
    )
    assert applications == []
    assert anomalies[0].auid == "AP100"
    assert anomalies[0].field == expected_field
    assert anomalies[0].distinct_value_count == 2
    assert stats["applications_with_inconsistent_data"] == 1


@pytest.mark.parametrize("missing", ["AUID", "Legacy APP ID", "DAP Name"])
def test_missing_required_column_fails_explicitly(missing):
    frame = pd.DataFrame([apm_row()]).drop(columns=[missing])
    with pytest.raises(ValueError, match=missing):
        parse_applications(frame, {"AP100"})


def test_jsonl_output_is_valid_and_findings_are_unchanged(tmp_path):
    csv_path = tmp_path / "real_apm.csv"
    pd.DataFrame([apm_row(), apm_row("AP200", "XYZ", "Outside")]).to_csv(csv_path, index=False)
    findings_path = tmp_path / "obj_findings.jsonl"
    original = write_findings(findings_path, ["AP100"])
    before = findings_path.read_bytes()

    applications_path, anomalies_path, analysis_path, report = write_outputs(
        csv_path, findings_path, tmp_path / "output",
    )

    assert json.loads(applications_path.read_text(encoding="utf-8")) == {
        "auid": "AP100", "trigram": "ABC", "name": "Payment App",
    }
    assert json.loads(anomalies_path.read_text(encoding="utf-8")) == []
    assert json.loads(analysis_path.read_text(encoding="utf-8"))["applications_generated"] == 1
    assert report["total_csv_rows"] == 2
    assert findings_path.read_bytes() == before
    assert json.loads(findings_path.read_text()) == original[0]


def test_cli_requires_findings_and_output_dir(tmp_path):
    csv_path = tmp_path / "apm.csv"
    pd.DataFrame([apm_row()]).to_csv(csv_path, index=False)
    with pytest.raises(SystemExit):
        main(["--input", str(csv_path)])
