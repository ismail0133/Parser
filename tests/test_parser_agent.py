import json

import pytest

from src.agents.parser_agent import run_parser_agent
from src.models.parser_result import ParserResult
from src.reporting.finding_analysis import OPEN_POINTS
from src.workflow.parser_graph import build_parser_graph
from tests.conftest import synthetic_row


def _parser_result(**overrides):
    values = {
        "status": "SUCCESS",
        "input_file": "input.csv",
        "input_rows": 1,
        "output_findings": 1,
        "findings_artifact": "findings.json",
        "errors": 0,
        "warnings": 0,
        "infos": 0,
        "retry_count": 0,
        "max_attempts": 3,
        "application_enrichment_status": "SKIPPED_NO_SOURCE",
        "anomalies_artifact": "anomalies.json",
        "analysis_report_artifact": "analysis.json",
        "open_points": OPEN_POINTS,
        "duration_seconds": 0.1,
    }
    values.update(overrides)
    return ParserResult(**values)


def _run_with_result(tmp_path, parser_result, kri_analysis=None, calls=None):
    input_path = tmp_path / "input.csv"
    input_path.write_text("x", encoding="utf-8")
    calls = calls if calls is not None else {"parser": 0, "kri": 0}

    def parser_runner(input_file, output_dir):
        calls["parser"] += 1
        return {"parser_result": parser_result, "artifacts": {"anomalies": "a", "jsonl": "f"}}

    def kri_analyzer(input_file, artifacts, output_dir):
        calls["kri"] += 1
        return kri_analysis

    graph = build_parser_graph(parser_runner=parser_runner, kri_analyzer=kri_analyzer)
    result = run_parser_agent(str(input_path), str(tmp_path / "out"), graph=graph)
    return result, calls


def test_agent_success(tmp_path):
    result, calls = _run_with_result(tmp_path, _parser_result())
    assert result.status == "SUCCESS"
    assert result.next_action == "CONTINUE"
    assert calls == {"parser": 1, "kri": 0}


def test_agent_success_with_warnings(tmp_path):
    result, _ = _run_with_result(
        tmp_path,
        _parser_result(status="SUCCESS_WITH_WARNINGS", warnings=2),
    )
    assert result.status == "SUCCESS_WITH_WARNINGS"
    assert result.next_action == "CONTINUE"


def test_kri_warning_is_analyzed_without_agent_retry(tmp_path):
    calls = {"parser": 0, "kri": 0}
    analysis = {
        "total_kri_mismatches": 50,
        "distribution_by_cause": {"GRAIN_MISMATCH": 50},
        "actually_correctable": 0,
        "requiring_business_validation": 50,
    }
    result, calls = _run_with_result(
        tmp_path,
        _parser_result(status="SUCCESS_WITH_WARNINGS", warnings=50, retry_count=0),
        analysis,
        calls,
    )
    assert calls == {"parser": 1, "kri": 1}
    assert result.parser.retry_count == 0
    assert result.kri.mismatches == 50
    assert result.kri.classification == "GRAIN_MISMATCH"
    assert result.next_action == "CONTINUE"


@pytest.mark.parametrize("parser_status", ["FAILED", "FAILED_AFTER_RETRIES"])
def test_failed_parser_stops_without_extra_retry(tmp_path, parser_status):
    result, calls = _run_with_result(
        tmp_path,
        _parser_result(status=parser_status, errors=1, retry_count=3),
    )
    assert result.status == "FAILED"
    assert result.next_action == "STOP"
    assert result.parser.retry_count == 3
    assert calls == {"parser": 1, "kri": 0}


def test_missing_cib_apm_does_not_fail(tmp_path):
    result, _ = _run_with_result(tmp_path, _parser_result())
    assert result.application_enrichment["status"] == "SKIPPED_NO_SOURCE"
    assert result.dependencies["cib_apm"] == "WAITING_FOR_SOURCE"
    assert result.status == "SUCCESS"


def test_missing_llm_does_not_fail(tmp_path):
    result, _ = _run_with_result(tmp_path, _parser_result())
    assert result.llm_status == "NOT_CONFIGURED"
    assert result.dependencies["llm_api"] == "NOT_CONFIGURED"


def test_missing_postgresql_uses_local_persistence(tmp_path):
    result, _ = _run_with_result(tmp_path, _parser_result())
    assert result.persistence_status == "LOCAL_ONLY"
    assert result.dependencies["postgresql"] == "NOT_CONFIGURED"


def test_missing_input_returns_clean_failure(tmp_path):
    result = run_parser_agent(str(tmp_path / "missing.csv"), str(tmp_path / "out"))
    assert result.status == "FAILED"
    assert result.next_action == "STOP"
    assert result.reason == "INPUT_FILE_NOT_FOUND"
    assert result.parser is None


def test_open_points_are_transmitted_without_failure(tmp_path):
    result, _ = _run_with_result(tmp_path, _parser_result())
    assert result.requires_business_validation is True
    assert {
        "unique_id", "remediation_id", "Proposed Owner",
        "remediation_strategy.strategy_type", "KRI RAS 9 source comparison grain",
    } <= set(result.open_points)
    assert result.status == "SUCCESS"


def test_agent_runs_real_parser_v1_and_writes_artifacts(csv_factory, tmp_path):
    raw_path = csv_factory([synthetic_row(**{"KRI RAS 9": "true"})])
    output = tmp_path / "agent-output"
    result = run_parser_agent(str(raw_path), str(output))
    assert result.status == "SUCCESS_WITH_WARNINGS"
    assert result.input.rows == 1
    assert result.parser.output_findings == 1
    assert result.parser.retry_count == 0
    assert result.kri.mismatches == 1
    assert result.kri.classification == "GRAIN_MISMATCH"
    assert result.next_action == "CONTINUE"
    agent_results = list(output.glob("PARSER-Agent_Result-*.json"))
    agent_reports = list(output.glob("PARSER-Agent_Report-*.md"))
    assert len(agent_results) == 1 and len(agent_reports) == 1
    assert json.loads(agent_results[0].read_text(encoding="utf-8"))["agent_version"] == "V0"
