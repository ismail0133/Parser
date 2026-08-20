import json
from pathlib import Path

import pytest

from scripts.load_obj_findings_to_postgres import JsonlInputError, main, prepare_input, read_jsonl
from tests.test_persistence_mapper import complete_finding


def write_jsonl(path: Path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def test_valid_jsonl_and_dry_run(tmp_path, capsys):
    path = write_jsonl(tmp_path / "findings.jsonl", [complete_finding()])
    assert main(["--input", str(path), "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "Input findings: 1" in output
    assert "Status: READY" in output


def test_invalid_json_line(tmp_path):
    path = tmp_path / "findings.jsonl"
    path.write_text("{bad}\n", encoding="utf-8")
    with pytest.raises(JsonlInputError, match="Line 1"):
        list(read_jsonl(path))


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        list(read_jsonl(Path("does-not-exist.jsonl")))


def test_zero_lines_is_ready_with_warning(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    mapped, stats, messages = prepare_input(path)
    assert mapped == []
    assert stats.warnings == 1
    assert messages


def test_same_cve_and_hostname_are_counted_as_one_dimension_shape(tmp_path):
    rows = [complete_finding(remediation_id="R1"), complete_finding(remediation_id="R2")]
    path = write_jsonl(tmp_path / "findings.jsonl", rows)
    mapped, stats, _ = prepare_input(path)
    assert len(mapped) == 2
    assert stats.servers == 1
    assert stats.vulnerabilities == 1
    assert stats.mapped_findings == 2


def test_non_enriched_application_is_unresolved(tmp_path):
    path = write_jsonl(tmp_path / "findings.jsonl", [complete_finding(application={"auid": "AP1"})])
    _, stats, _ = prepare_input(path)
    assert stats.applications_available == 0
    assert stats.applications_unresolved == 1
