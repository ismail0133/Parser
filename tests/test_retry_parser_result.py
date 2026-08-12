import json

from main import write_outputs
from src.models.finding import Anomaly
from src.parser import parse_findings
from src.validation.retry import MAX_PARSE_ATTEMPTS, parse_with_retries
from tests.conftest import synthetic_row


def anomaly(severity="ERROR", classification="ERROR_REMEDIABLE", error_type="FIXABLE"):
    return Anomaly(
        row_index=1, field="x", severity=severity, error_type=error_type,
        message="test", classification=classification,
    )


def test_retry_success_on_first_attempt():
    result, anomalies, trace = parse_with_retries(
        "ok", lambda value: (value, []), lambda value, errors: None,
    )
    assert result == "ok" and anomalies == []
    assert len(trace) == 1 and trace[0].final_status == "SUCCESS"


def test_retry_applies_real_deterministic_correction():
    def parse(value):
        return value, [] if value == "clean" else [anomaly()]

    result, anomalies, trace = parse_with_retries(
        "dirty", parse, lambda value, errors: ("clean", ["trim_documented_whitespace"]),
    )
    assert result == "clean" and anomalies == []
    assert len(trace) == 2
    assert trace[0].corrections_applied == ["trim_documented_whitespace"]
    assert trace[-1].final_status == "SUCCESS"


def test_retry_fails_after_three_effective_corrections():
    calls = {"count": 0}

    def correct(value, errors):
        calls["count"] += 1
        return value + 1, [f"correction_{calls['count']}"]

    _, anomalies, trace = parse_with_retries(
        0, lambda value: (value, [anomaly()]), correct,
    )
    assert anomalies and len(trace) == MAX_PARSE_ATTEMPTS
    assert trace[-1].final_status == "FAILED_AFTER_RETRIES"


def test_warning_and_to_validate_do_not_retry():
    for item in (
        anomaly("WARNING", "WARNING", "KRI_MISMATCH"),
        anomaly("ERROR", "TO_VALIDATE", "TO_VALIDATE_RULE"),
    ):
        _, _, trace = parse_with_retries(
            "value", lambda value, item=item: (value, [item]),
            lambda value, errors: (_ for _ in ()).throw(AssertionError("must not retry")),
        )
        assert len(trace) == 1


def test_parser_result_and_skipped_application_source(csv_factory, tmp_path):
    findings, anomalies, stats = parse_findings(csv_factory([synthetic_row()]))
    assert stats["application_enrichment"]["status"] == "SKIPPED_NO_SOURCE"
    assert stats["retry"]["retry_count"] == 0
    paths = write_outputs(
        findings, anomalies, stats, tmp_path,
        input_path="data/finding_list_fixed.csv", run_timestamp="20260812-120000",
    )
    result = json.loads(paths["parser_result"].read_text(encoding="utf-8"))
    assert result["component"] == "PARSER"
    assert result["application_enrichment_status"] == "SKIPPED_NO_SOURCE"
    assert result["max_attempts"] == 3
    assert paths["parser_result"].name == "PARSER-Result-20260812-120000.json"
