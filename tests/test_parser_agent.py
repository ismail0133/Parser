import json

import pytest

from src.agents.parser_agent import render_execution_summary, run_parser_agent
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
        "kri_ras9": {"aggregate": {
            "percentage": 0.0, "business_target_met": True,
        }},
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
        "server_level_mismatches": 50,
        "warning_distribution": {"KRI_SERVER_MISMATCH": 50},
        "classification": "SATISFACTORY",
        "actually_correctable": 0,
        "kri_percentage": 20.0,
        "business_target_met": True,
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
    assert result.kri.classification == "SATISFACTORY"
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


def test_summary_keeps_failed_parser_distinct_from_external_enrichment(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    enrichment_report = {
        "status": "SUCCESS",
        "total_findings": 7,
        "findings_with_auid": 5,
        "findings_without_auid": 2,
        "matched_findings": 4,
        "unmatched_findings": 1,
        "enriched_findings": 4,
        "application_conflicts": 1,
        "field_conflicts": 2,
        "match_rate": 80.0,
        "output_findings": 7,
        "input_equals_output": True,
    }
    (output / "application_enrichment_report.json").write_text(
        json.dumps(enrichment_report), encoding="utf-8"
    )
    result, _ = _run_with_result(
        tmp_path,
        _parser_result(status="FAILED", output_findings=7, warnings=3, errors=2),
    )

    summary = render_execution_summary(result)

    assert "Status              : FAILED" in summary
    assert "Warnings            : 3" in summary
    assert "Errors              : 2" in summary
    assert "SKIPPED_NO_SOURCE" not in summary
    assert "APPLICATION ENRICHMENT (EXTERNAL)" in summary
    assert "Status              : SUCCESS" in summary
    assert "Findings with AUID  : 5" in summary
    assert "Findings without AUID: 2" in summary
    assert "Matched findings    : 4" in summary
    assert "Unmatched findings  : 1" in summary
    assert "Enriched findings   : 4" in summary
    assert "Match rate          : 80.0%" in summary
    assert "Application conflicts: 1" in summary
    assert "Field conflicts     : 2" in summary
    assert "Data loss           : NO" in summary
    assert result.status == "FAILED"


def test_summary_reports_external_enrichment_not_available(tmp_path):
    result, _ = _run_with_result(tmp_path, _parser_result(output_findings=9))

    summary = render_execution_summary(result)

    assert result.external_application_enrichment == {"status": "NOT_AVAILABLE"}
    assert "APPLICATION ENRICHMENT (EXTERNAL)" in summary
    assert "Status              : NOT_AVAILABLE" in summary
    assert "Data loss           : NOT_AVAILABLE" in summary
    assert "Pipeline output     : 9 findings" in summary


def test_summary_does_not_modify_result(tmp_path):
    result, _ = _run_with_result(tmp_path, _parser_result(warnings=6, errors=4))
    before = result.model_dump()

    render_execution_summary(result)

    assert result.model_dump() == before


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
    assert "unique_id" not in result.open_points
    assert "remediation_id" not in result.open_points
    assert "Proposed Owner" not in result.open_points
    assert "remediation_strategy.strategy_type" not in result.open_points
    assert "KRI RAS 9 source comparison grain" not in result.open_points
    assert result.status == "SUCCESS"


def test_agent_runs_real_parser_v1_and_writes_artifacts(csv_factory, tmp_path):
    raw_path = csv_factory([synthetic_row(**{"KRI RAS 9": "true"})])
    output = tmp_path / "agent-output"
    result = run_parser_agent(str(raw_path), str(output))
    assert result.status == "SUCCESS"
    assert result.input.rows == 1
    assert result.parser.output_findings == 1
    assert result.parser.retry_count == 0
    assert result.parser.warnings == 0
    assert result.kri.mismatches == 0
    assert result.kri.classification is None
    assert result.next_action == "CONTINUE"
    agent_results = list(output.glob("PARSER-Agent_Result-*.json"))
    agent_reports = list(output.glob("PARSER-Agent_Report-*.md"))
    assert len(agent_results) == 1 and len(agent_reports) == 1
    assert json.loads(agent_results[0].read_text(encoding="utf-8"))["agent_version"] == "V0"
