import json

import pytest

from src.models.finding import Anomaly
from src.persistence.parser_artifact_validator import (
    ParserArtifactValidationError,
    load_and_validate_parser_artifacts,
    map_anomaly_to_sql,
    read_parser_anomalies,
    read_parser_result,
    validate_parser_artifact_consistency,
    validate_parser_data_consistency,
)


def parser_result_payload(**overrides):
    payload = {
        "component": "PARSER",
        "status": "SUCCESS_WITH_WARNINGS",
        "input_file": "data/findings.csv",
        "input_rows": 2,
        "output_findings": 2,
        "findings_artifact": "PARSER-Findings-20260908-120000.json",
        "errors": 0,
        "warnings": 1,
        "infos": 1,
        "retry_count": 0,
        "max_attempts": 3,
        "application_enrichment_status": "SKIPPED_NO_SOURCE",
        "anomalies_artifact": "parser_anomalies.json",
        "analysis_report_artifact": "PARSER-Finding_Analysis-20260908-120000.json",
        "open_points": [],
        "kri_ras9": {},
        "duration_seconds": 0.1,
    }
    payload.update(overrides)
    return payload


def anomaly_payload(severity="WARNING", **overrides):
    payload = {
        "row_index": 1,
        "rem_key_id": "REM-1",
        "field": "KRI RAS 9",
        "value": {"source": False, "calculated": True},
        "severity": severity,
        "error_type": "KRI_SERVER_MISMATCH",
        "message": "Source and calculated KRI differ.",
        "classification": severity if severity in {"WARNING", "INFO"} else "ERROR_NON_REMEDIABLE",
    }
    payload.update(overrides)
    return payload


def write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_loads_and_validates_real_parser_contracts(tmp_path):
    result_path = write_json(tmp_path / "PARSER-Result.json", parser_result_payload())
    anomalies_path = write_json(tmp_path / "parser_anomalies.json", [
        anomaly_payload(),
        anomaly_payload(
            severity="INFO",
            error_type="AGE_RECALCULATED",
            classification="INFO",
        ),
    ])

    result, anomalies = load_and_validate_parser_artifacts(
        result_path, anomalies_path, output_findings_count=2,
    )

    assert result.component == "PARSER"
    assert [anomaly.severity for anomaly in anomalies] == ["WARNING", "INFO"]


def test_parser_result_root_must_be_an_object(tmp_path):
    path = write_json(tmp_path / "result.json", [])

    with pytest.raises(ParserArtifactValidationError, match="root must be a JSON object"):
        read_parser_result(path)


def test_invalid_parser_result_reports_contract_error(tmp_path):
    path = write_json(tmp_path / "result.json", parser_result_payload(status="UNKNOWN"))

    with pytest.raises(ParserArtifactValidationError, match="Invalid ParserResult contract"):
        read_parser_result(path)


def test_parser_anomalies_root_must_be_a_list(tmp_path):
    path = write_json(tmp_path / "parser_anomalies.json", {"anomalies": []})

    with pytest.raises(ParserArtifactValidationError, match="root must be a JSON list"):
        read_parser_anomalies(path)


def test_each_parser_anomaly_is_validated_with_its_index(tmp_path):
    path = write_json(tmp_path / "parser_anomalies.json", [anomaly_payload(severity="INVALID")])

    with pytest.raises(ParserArtifactValidationError, match="anomaly item 1"):
        read_parser_anomalies(path)


def test_declared_anomalies_basename_must_match_provided_file(tmp_path):
    result = read_parser_result(write_json(
        tmp_path / "result.json",
        parser_result_payload(anomalies_artifact="other_anomalies.json"),
    ))

    with pytest.raises(ParserArtifactValidationError, match="does not match"):
        validate_parser_artifact_consistency(
            result,
            [],
            parser_result_path=tmp_path / "result.json",
            anomalies_path=tmp_path / "parser_anomalies.json",
            output_findings_count=2,
        )


def test_same_anomalies_basename_in_another_directory_is_rejected(tmp_path):
    result_path = write_json(tmp_path / "result.json", parser_result_payload())
    other_directory = tmp_path / "other"
    other_directory.mkdir()

    with pytest.raises(ParserArtifactValidationError, match="does not match"):
        validate_parser_artifact_consistency(
            read_parser_result(result_path),
            [],
            parser_result_path=result_path,
            anomalies_path=other_directory / "parser_anomalies.json",
            output_findings_count=2,
        )


def test_data_validation_does_not_require_artifact_paths(tmp_path):
    result = read_parser_result(write_json(
        tmp_path / "result.json",
        parser_result_payload(
            warnings=0,
            infos=0,
        ),
    ))

    validate_parser_data_consistency(
        result,
        [],
        output_findings_count=2,
    )


def test_relative_anomalies_path_is_resolved_from_parser_result_directory(tmp_path):
    artifacts_directory = tmp_path / "artifacts"
    artifacts_directory.mkdir()
    result_path = write_json(
        tmp_path / "result.json",
        parser_result_payload(
            warnings=0,
            infos=0,
            anomalies_artifact="artifacts/parser_anomalies.json",
        ),
    )
    anomalies_path = write_json(
        artifacts_directory / "parser_anomalies.json",
        [],
    )

    result, anomalies = load_and_validate_parser_artifacts(
        result_path,
        anomalies_path,
        output_findings_count=2,
    )

    assert result.anomalies_artifact == "artifacts/parser_anomalies.json"
    assert anomalies == []


@pytest.mark.parametrize(
    ("counter_overrides", "anomalies", "expected_message"),
    [
        ({"errors": 1}, [], "ERROR: ParserResult=1, anomalies=0"),
        ({"warnings": 2}, [anomaly_payload()], "WARNING: ParserResult=2, anomalies=1"),
        ({"infos": 2}, [anomaly_payload(), anomaly_payload(severity="INFO")],
         "INFO: ParserResult=2, anomalies=1"),
    ],
)
def test_anomaly_counter_mismatches_are_explicit(
    tmp_path, counter_overrides, anomalies, expected_message,
):
    result = read_parser_result(write_json(
        tmp_path / "result.json", parser_result_payload(**counter_overrides),
    ))
    parsed_anomalies = [Anomaly.model_validate(item) for item in anomalies]

    with pytest.raises(ParserArtifactValidationError, match=expected_message):
        validate_parser_artifact_consistency(
            result,
            parsed_anomalies,
            parser_result_path=tmp_path / "result.json",
            anomalies_path=tmp_path / "parser_anomalies.json",
            output_findings_count=2,
        )


def test_output_findings_count_must_match(tmp_path):
    result = read_parser_result(write_json(
        tmp_path / "result.json",
        parser_result_payload(warnings=0, infos=0),
    ))

    with pytest.raises(ParserArtifactValidationError, match="output_findings"):
        validate_parser_artifact_consistency(
            result,
            [],
            parser_result_path=tmp_path / "result.json",
            anomalies_path=tmp_path / "parser_anomalies.json",
            output_findings_count=1,
        )


@pytest.mark.parametrize("invalid_count", [-1, 1.5, True])
def test_output_findings_count_must_be_a_non_negative_integer(tmp_path, invalid_count):
    result = read_parser_result(write_json(
        tmp_path / "result.json",
        parser_result_payload(warnings=0, infos=0),
    ))

    with pytest.raises(ParserArtifactValidationError, match="non-negative integer"):
        validate_parser_artifact_consistency(
            result,
            [],
            parser_result_path=tmp_path / "result.json",
            anomalies_path=tmp_path / "parser_anomalies.json",
            output_findings_count=invalid_count,
        )


def test_maps_anomaly_to_exact_sql_row_with_injectable_ids():
    anomaly = Anomaly.model_validate(anomaly_payload())

    row = map_anomaly_to_sql(
        anomaly,
        pipeline_run_id="pipeline-1",
        agent_run_id=12,
    )

    assert row == {
        "pipeline_run_id": "pipeline-1",
        "agent_run_id": 12,
        "finding_id": None,
        "anomaly_level": "WARNING",
        "code": "KRI_SERVER_MISMATCH",
        "message": "Source and calculated KRI differ.",
        "details": {
            "row_index": 1,
            "rem_key_id": "REM-1",
            "field": "KRI RAS 9",
            "value": {"source": False, "calculated": True},
            "classification": "WARNING",
        },
    }


def test_mapper_defaults_pipeline_and_agent_ids_and_forces_finding_id_to_none():
    row = map_anomaly_to_sql(Anomaly.model_validate(anomaly_payload()))

    assert row["pipeline_run_id"] is None
    assert row["agent_run_id"] is None
    assert row["finding_id"] is None
