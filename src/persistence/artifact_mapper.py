"""Build immutable metadata for files registered as PostgreSQL artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PARSER_RESULT_JSON = "PARSER_RESULT_JSON"
PARSER_ANOMALIES_JSON = "PARSER_ANOMALIES_JSON"
OBJ_APPLICATIONS_JSONL = "OBJ_APPLICATIONS_JSONL"
OBJ_FINDINGS_JSONL = "OBJ_FINDINGS_JSONL"
OBJ_FINDINGS_ENRICHED_JSONL = "OBJ_FINDINGS_ENRICHED_JSONL"
OBJ_SERVERS_JSONL = "OBJ_SERVERS_JSONL"
APPLICATION_SERVER_RELATIONS_JSONL = "APPLICATION_SERVER_RELATIONS_JSONL"


class ArtifactMetadataError(ValueError):
    """Raised when Artifact metadata cannot be calculated from a source file."""


@dataclass(frozen=True)
class PreparedArtifact:
    artifact_type: str
    filename: str
    storage_path: str
    sha256: str
    row_count: int | None
    produced_by_parser: bool = False

    def to_repository_row(
        self,
        *,
        pipeline_run_id: Any,
        parser_agent_run_id: Any,
    ) -> dict[str, Any]:
        return {
            "artifact_type": self.artifact_type,
            "filename": self.filename,
            "storage_path": self.storage_path,
            "sha256": self.sha256,
            "pipeline_run_id": pipeline_run_id,
            "agent_run_id": parser_agent_run_id if self.produced_by_parser else None,
            "row_count": self.row_count,
        }


def _structured_row_count(path: Path, content: bytes) -> int | None:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ArtifactMetadataError(
                f"Artifact JSONL is not valid UTF-8: {path}"
            ) from exc
        return sum(1 for line in text.splitlines() if line.strip())
    if suffix == ".json":
        try:
            payload = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArtifactMetadataError(f"Artifact contains invalid JSON: {path}") from exc
        if isinstance(payload, list):
            return len(payload)
        if isinstance(payload, dict):
            return 1
    return None


def prepare_artifact(
    path: str | Path,
    artifact_type: str,
    *,
    produced_by_parser: bool = False,
) -> PreparedArtifact:
    """Hash one file and calculate its structured record count from the same bytes."""
    source = Path(path)
    if not source.is_file():
        raise ArtifactMetadataError(f"Artifact file not found: {source}")
    try:
        content = source.read_bytes()
    except OSError as exc:
        raise ArtifactMetadataError(f"Unable to read Artifact file {source}: {exc}") from exc
    return PreparedArtifact(
        artifact_type=artifact_type,
        filename=source.name,
        storage_path=str(source.resolve()),
        sha256=hashlib.sha256(content).hexdigest(),
        row_count=_structured_row_count(source, content),
        produced_by_parser=produced_by_parser,
    )


def artifact_matches_parser_declaration(
    candidate_path: str | Path,
    *,
    parser_result_path: str | Path,
    declared_path: str,
) -> bool:
    """Match an artifact only through the exact path declared by ParserResult."""
    result_path = Path(parser_result_path).resolve()
    declared = Path(declared_path)
    expected = (
        declared.resolve()
        if declared.is_absolute()
        else (result_path.parent / declared).resolve()
    )
    return Path(candidate_path).resolve() == expected
