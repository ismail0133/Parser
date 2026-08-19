import json

import pandas as pd

from scripts.build_obj_applications import write_outputs
from src.application_parser import analyze_finding_coverage, parse_applications
from tests.conftest import synthetic_row


def frame(*rows):
    return pd.DataFrame(rows)


def test_unique_auid_maps_only_real_application_values():
    applications, anomalies, stats = parse_applications(frame(synthetic_row()))
    assert len(applications) == 1
    assert applications[0].model_dump() == {
        "auid": "AP10426",
        "code_app": "AP99999",
        "trigram": "ABC",
        "application_name": "Synthetic App",
        "appsec": "P4",
        "business_line": None,
        "production_domain_manager": None,
        "production_manager": None,
    }
    assert anomalies == []
    assert stats["output_applications"] == 1


def test_many_findings_with_same_auid_produce_one_application():
    applications, anomalies, _ = parse_applications(frame(
        synthetic_row(REM_KEY_ID="1"), synthetic_row(REM_KEY_ID="2"),
    ))
    assert len(applications) == 1
    assert anomalies == []


def test_missing_auid_is_excluded_without_code_app_fallback():
    applications, anomalies, stats = parse_applications(frame(
        synthetic_row(AUID="", CODE_APP="AP99999"),
    ))
    assert applications == []
    assert stats["missing_auid_rows"] == 1
    assert anomalies[0].error_type == "MISSING_AUID"


def test_empty_name_and_nan_become_none_without_invented_values():
    row = synthetic_row(**{"Application Name": float("nan"), "AppSec Profile": " "})
    applications, _, stats = parse_applications(frame(row))
    assert applications[0].application_name is None
    assert applications[0].appsec is None
    assert stats["null_count_by_field"]["application_name"] == 1


def test_identical_values_do_not_conflict():
    applications, anomalies, _ = parse_applications(frame(
        synthetic_row(REM_KEY_ID="1"), synthetic_row(REM_KEY_ID="2"),
    ))
    assert applications[0].application_name == "Synthetic App"
    assert not [item for item in anomalies if item.error_type == "APPLICATION_CONFLICT"]


def test_conflicting_fields_become_none_and_are_all_reported():
    rows = [
        synthetic_row(REM_KEY_ID="1", **{
            "Application Name": "App One", "Business Lines": "BL1",
            "Production Manager": "Manager One",
        }),
        synthetic_row(REM_KEY_ID="2", **{
            "Application Name": "App Two", "Business Lines": "BL2",
            "Production Manager": "Manager Two",
        }),
    ]
    applications, anomalies, stats = parse_applications(frame(*rows))
    application = applications[0]
    assert application.application_name is None
    assert application.business_line is None
    assert application.production_manager is None
    conflicts = {item.field: item.values for item in anomalies}
    assert conflicts == {
        "application_name": ["App One", "App Two"],
        "business_line": ["BL1", "BL2"],
        "production_manager": ["Manager One", "Manager Two"],
    }
    assert stats["applications_with_conflicts"] == 1


def test_invalid_auid_is_excluded():
    applications, anomalies, stats = parse_applications(frame(synthetic_row(AUID="not-an-auid")))
    assert applications == []
    assert stats["invalid_auid_rows"] == 1
    assert anomalies[0].error_type == "INVALID_AUID"


def test_finding_application_coverage(tmp_path):
    findings = tmp_path / "obj_findings.jsonl"
    findings.write_text("".join([
        json.dumps({"application": {"auid": "AP10426"}}) + "\n",
        json.dumps({"application": {"auid": "AP99999"}}) + "\n",
        json.dumps({"application": {"auid": "AP10426"}}) + "\n",
    ]), encoding="utf-8")
    applications, _, _ = parse_applications(frame(synthetic_row()))
    coverage = analyze_finding_coverage(findings, applications)
    assert coverage["distinct_auid_in_obj_findings"] == 2
    assert coverage["matched_auid"] == 1
    assert coverage["unmatched_auid"] == 1
    assert coverage["match_rate_percent"] == 50.0


def test_outputs_are_valid_jsonl_and_report(csv_factory, tmp_path):
    csv_path = csv_factory([synthetic_row(), synthetic_row(REM_KEY_ID="2")])
    applications_path, anomalies_path, analysis_path, report = write_outputs(
        csv_path, tmp_path / "output"
    )
    lines = applications_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["auid"] == "AP10426"
    assert json.loads(anomalies_path.read_text(encoding="utf-8")) == []
    assert json.loads(analysis_path.read_text(encoding="utf-8"))["input_rows"] == 2
    assert report["finding_coverage"] is None
