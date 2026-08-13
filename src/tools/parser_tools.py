import json
from pathlib import Path
from typing import Any

from analyze_kri_mismatches import SERVER_KRI_WARNING_TYPES, analyze
from main import write_outputs
from src.models.parser_result import ParserResult
from src.parser import parse_findings


def run_parser(input_file: str, output_dir: str = "output") -> dict[str, Any]:
    """Run Parser V1 once and return its persisted contract and artifact paths."""
    findings, anomalies, stats = parse_findings(input_file)
    artifacts = write_outputs(
        findings, anomalies, stats, output_dir, input_path=input_file
    )
    parser_result = ParserResult.model_validate_json(
        artifacts["parser_result"].read_text(encoding="utf-8")
    )
    return {
        "parser_result": parser_result,
        "artifacts": {key: str(path.resolve()) for key, path in artifacts.items()},
    }


def analyze_parser_kri_warnings(
    input_file: str, artifacts: dict[str, str], output_dir: str
) -> dict[str, Any] | None:
    """Run the KRI server analysis when a server-level KRI warning exists."""
    anomalies_path = Path(artifacts["anomalies"])
    anomalies = json.loads(anomalies_path.read_text(encoding="utf-8"))
    if not any(item.get("error_type") in SERVER_KRI_WARNING_TYPES for item in anomalies):
        return None
    return analyze(
        Path(input_file),
        Path(artifacts["jsonl"]),
        anomalies_path,
        Path(output_dir),
    )
