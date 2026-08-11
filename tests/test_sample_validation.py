import json

from main import write_outputs
from src.parser import parse_findings
from tests.conftest import synthetic_row
from validate_sample_findings import select_sample, validate_sample


def test_sample_selection_uses_representative_criteria():
    raw = [
        {"PRIORITY": "PR1", "ENVIRONMENT": "PRODUCTION", "ETA": "", "SLA": "", "XTRACT_PATH": "/apps/a"},
        {"PRIORITY": "PR4", "ENVIRONMENT": "RECETTE", "ETA": "2026-08-01", "SLA": "90", "XTRACT_PATH": "/etc/a"},
    ]
    objects = [
        {"overdue": True, "false_positive": False, "false_positive_to_confirm": False},
        {"overdue": False, "false_positive": True, "false_positive_to_confirm": False},
    ]
    selected, unavailable = select_sample(raw, objects, {}, size=2)
    assert [item[0] for item in selected] == [1, 2]
    reasons = {reason for _, labels in selected for reason in labels}
    assert {"priority_PR1", "priority_PR4", "environment_production", "eta_present"} <= reasons
    assert "priority_PR2" in unavailable


def test_validation_generates_json_and_markdown(csv_factory, tmp_path):
    rows = [
        synthetic_row(REM_KEY_ID="one", PRIORITY="PR1", XTRACT_PATH="/apps/a"),
        synthetic_row(REM_KEY_ID="two", PRIORITY="PR4", ENVIRONMENT="RECETTE", ETA=""),
    ]
    raw_path = csv_factory(rows)
    findings, anomalies, stats = parse_findings(raw_path)
    output = tmp_path / "output"
    write_outputs(
        findings, anomalies, stats, output,
        input_path=raw_path, run_timestamp="20260811-120000",
    )

    report = validate_sample(raw_path, output / "obj_findings.jsonl", output, sample_size=2)

    assert report["summary"]["sample_size"] == 2
    assert (output / "PARSER-Sample_Validation.json").is_file()
    assert (output / "PARSER-Sample_Validation.md").is_file()
    persisted = json.loads((output / "PARSER-Sample_Validation.json").read_text(encoding="utf-8"))
    assert persisted["cases"][0]["raw"]["REM_KEY_ID"] == "one"
    markdown = (output / "PARSER-Sample_Validation.md").read_text(encoding="utf-8")
    assert "# Parser Sample Validation" in markdown
    assert "## Sample selection" in markdown
