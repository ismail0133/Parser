"""Read, validate, and map Parser artifacts for PostgreSQL persistence."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from src.models.finding import Anomaly
from src.models.parser_result import ParserResult


class ParserArtifactValidationError(ValueError):
    """Raised when Parser artifacts are malformed or mutually inconsistent."""


def _read_json(path: str | Path, artifact_name: str) -> Any:
    artifact_path = Path(path)
    if not artifact_path.is_file():
        raise ParserArtifactValidationError(
            f"{artifact_name} file not found: {artifact_path}"
        )
    try:
        return json.loads(artifact_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ParserArtifactValidationError(
            f"Invalid {artifact_name} JSON in {artifact_path}: {exc.msg}"
        ) from exc
    except OSError as exc:
        raise ParserArtifactValidationError(
            f"Unable to read {artifact_name} file {artifact_path}: {exc}"
        ) from exc


def read_parser_result(path: str | Path) -> ParserResult:
    """Read one ParserResult JSON object and validate its existing Pydantic contract."""
    artifact_path = Path(path)
    payload = _read_json(artifact_path, "ParserResult")
    if not isinstance(payload, dict):
        raise ParserArtifactValidationError(
            f"ParserResult root must be a JSON object: {artifact_path}"
        )
    try:
        return ParserResult.model_validate(payload)
    except ValidationError as exc:
        raise ParserArtifactValidationError(
            f"Invalid ParserResult contract in {artifact_path}: {exc}"
        ) from exc


def read_parser_anomalies(path: str | Path) -> list[Anomaly]:
    """Read a Parser anomaly JSON list and validate every entry as an Anomaly."""
    artifact_path = Path(path)
    payload = _read_json(artifact_path, "Parser anomalies")
    if not isinstance(payload, list):
        raise ParserArtifactValidationError(
            f"Parser anomalies root must be a JSON list: {artifact_path}"
        )

    anomalies: list[Anomaly] = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            raise ParserArtifactValidationError(
                f"Parser anomaly item {index} must be a JSON object: {artifact_path}"
            )
        try:
            anomalies.append(Anomaly.model_validate(item))
        except ValidationError as exc:
            raise ParserArtifactValidationError(
                f"Invalid Parser anomaly item {index} in {artifact_path}: {exc}"
            ) from exc
    return anomalies


def validate_parser_artifact_consistency(
    parser_result: ParserResult,
    anomalies: list[Anomaly],
    *,
    parser_result_path: str | Path,
    anomalies_path: str | Path,
    output_findings_count: int,
) -> None:
    """Validate artifact association and all externally verifiable counters."""
    result_file = Path(parser_result_path).resolve()
    declared_path = Path(parser_result.anomalies_artifact)
    declared_anomalies = (
        declared_path.resolve()
        if declared_path.is_absolute()
        else (result_file.parent / declared_path).resolve()
    )
    provided_anomalies = Path(anomalies_path).resolve()
    if declared_anomalies != provided_anomalies:
        raise ParserArtifactValidationError(
            "ParserResult anomalies_artifact does not match the provided anomalies file: "
            f"declared={str(declared_anomalies)!r}, "
            f"provided={str(provided_anomalies)!r}"
        )

    validate_parser_data_consistency(
        parser_result,
        anomalies,
        output_findings_count=output_findings_count,
    )


def validate_parser_data_consistency(
    parser_result: ParserResult,
    anomalies: list[Anomaly],
    *,
    output_findings_count: int,
) -> None:
    """Validate Parser counters when the already-loaded models are available."""
    if isinstance(output_findings_count, bool) or not isinstance(output_findings_count, int):
        raise ParserArtifactValidationError(
            "output_findings_count must be a non-negative integer"
        )
    if output_findings_count < 0:
        raise ParserArtifactValidationError(
            "output_findings_count must be a non-negative integer"
        )

    counts = Counter(anomaly.severity for anomaly in anomalies)
    expected_counts = {
        "ERROR": parser_result.errors,
        "WARNING": parser_result.warnings,
        "INFO": parser_result.infos,
    }
    count_mismatches = [
        f"{severity}: ParserResult={expected}, anomalies={counts[severity]}"
        for severity, expected in expected_counts.items()
        if expected != counts[severity]
    ]
    if count_mismatches:
        raise ParserArtifactValidationError(
            "ParserResult anomaly counters do not match parser_anomalies.json: "
            + "; ".join(count_mismatches)
        )

    if parser_result.output_findings != output_findings_count:
        raise ParserArtifactValidationError(
            "ParserResult output_findings does not match the supplied findings count: "
            f"ParserResult={parser_result.output_findings}, "
            f"supplied={output_findings_count}"
        )


def load_and_validate_parser_artifacts(
    parser_result_path: str | Path,
    anomalies_path: str | Path,
    *,
    output_findings_count: int,
) -> tuple[ParserResult, list[Anomaly]]:
    """Load both Parser artifacts and validate their cross-artifact consistency."""
    parser_result = read_parser_result(parser_result_path)
    anomalies = read_parser_anomalies(anomalies_path)
    validate_parser_artifact_consistency(
        parser_result,
        anomalies,
        parser_result_path=parser_result_path,
        anomalies_path=anomalies_path,
        output_findings_count=output_findings_count,
    )
    return parser_result, anomalies


def map_anomaly_to_sql(
    anomaly: Anomaly,
    *,
    pipeline_run_id: Any = None,
    agent_run_id: Any = None,
) -> dict[str, Any]:
    """Map a Parser Anomaly; Parser artifacts cannot resolve a finding foreign key."""
    serialized = anomaly.model_dump(mode="json")
    details = {
        "row_index": serialized["row_index"],
        "rem_key_id": serialized["rem_key_id"],
        "field": serialized["field"],
        "value": serialized["value"],
        "classification": serialized["classification"],
    }
    if serialized["source_row_number"] is not None:
        details["source_row_number"] = serialized["source_row_number"]
    return {
        "pipeline_run_id": pipeline_run_id,
        "agent_run_id": agent_run_id,
        "finding_id": None,
        "anomaly_level": anomaly.severity,
        "code": anomaly.error_type,
        "message": anomaly.message,
        "details": details,
    }
