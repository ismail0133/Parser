#!/usr/bin/env python3
"""Validate, map and transactionally load Parser obj_findings JSONL."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import UUID, uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.persistence.database import connect
from src.persistence.finding_mapper import map_obj_finding
from src.persistence.postgres_repository import PostgresFindingRepository


@dataclass
class LoadStats:
    input_findings: int = 0
    mapped_findings: int = 0
    servers: int = 0
    vulnerabilities: int = 0
    applications_available: int = 0
    applications_unresolved: int = 0
    mapping_errors: int = 0
    warnings: int = 0


class JsonlInputError(ValueError):
    pass


def read_jsonl(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")
    with path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, start=1):
            if not line.strip():
                raise JsonlInputError(f"Line {line_no}: empty JSONL line")
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise JsonlInputError(f"Line {line_no}: invalid JSON: {exc.msg}") from exc
            if not isinstance(payload, dict):
                raise JsonlInputError(f"Line {line_no}: obj_finding must be a JSON object")
            yield line_no, payload


def prepare_input(path: Path) -> tuple[list[dict[str, Any]], LoadStats, list[str]]:
    mapped: list[dict[str, Any]] = []
    stats = LoadStats()
    messages: list[str] = []
    seen_servers: set[str] = set()
    seen_vulnerabilities: set[str] = set()
    seen_applications: set[str] = set()
    for line_no, payload in read_jsonl(path):
        stats.input_findings += 1
        try:
            relational = map_obj_finding(payload)
            # This also proves all SQL-bound structures are serializable/preparable.
            json.dumps(relational, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            stats.mapping_errors += 1
            messages.append(f"Line {line_no}: {exc}")
            continue
        mapped.append(relational)
        stats.mapped_findings += 1
        if relational["server"] is not None:
            seen_servers.add(json.dumps(relational["server"], sort_keys=True, ensure_ascii=False))
        if relational["vulnerability"] is not None:
            seen_vulnerabilities.add(json.dumps(relational["vulnerability"], sort_keys=True, ensure_ascii=False))
        if relational["application"] is not None:
            seen_applications.add(json.dumps(relational["application"], sort_keys=True, ensure_ascii=False))
        else:
            stats.applications_unresolved += 1
    stats.servers = len(seen_servers)
    stats.vulnerabilities = len(seen_vulnerabilities)
    stats.applications_available = len(seen_applications)
    if stats.input_findings == 0:
        stats.warnings += 1
        messages.append("Input contains no findings")
    return mapped, stats, messages


def load_transaction(
    connection: Any, mapped: list[dict[str, Any]], source: Path,
    run_id: UUID | None = None,
) -> UUID:
    repository = PostgresFindingRepository(connection)
    pipeline_run_id = run_id or uuid4()
    now = datetime.now(timezone.utc)
    server_ids: dict[str, Any] = {}
    application_ids: dict[str, Any] = {}
    try:
        repository.create_pipeline_run({
            "pipeline_run_id": pipeline_run_id, "started_at": now, "ended_at": None,
            "run_status": "RUNNING", "source_filename": source.name,
            "input_rows": len(mapped), "output_findings": 0, "error_count": 0, "warning_count": 0,
        })
        agent_id = repository.get_or_create_agent("PARSER")
        agent_run_id = repository.create_agent_run({
            "pipeline_run_id": pipeline_run_id, "agent_id": agent_id, "attempt_no": 1,
            "started_at": now, "ended_at": None, "run_status": "RUNNING",
            "feedback_type": None, "feedback_message": None,
        })
        for relational in mapped:
            application_id = None
            if relational["application"] is not None:
                key = json.dumps(relational["application"], sort_keys=True, ensure_ascii=False)
                if key not in application_ids:
                    application_ids[key] = repository.get_or_create_application(relational["application"])
                application_id = application_ids[key]
            server_id = None
            if relational["server"] is not None:
                key = json.dumps(relational["server"], sort_keys=True, ensure_ascii=False)
                if key not in server_ids:
                    server_ids[key] = repository.create_server(relational["server"])
                server_id = server_ids[key]
            vulnerability_id = None
            if relational["vulnerability"] is not None:
                vulnerability_id = repository.get_or_create_vulnerability(relational["vulnerability"])
            finding = dict(relational["finding"])
            finding.update({
                "pipeline_run_id": pipeline_run_id, "application_id": application_id,
                "server_id": server_id, "vulnerability_id": vulnerability_id,
            })
            repository.insert_finding(finding)
        ended_at = datetime.now(timezone.utc)
        repository.finish_agent_run(agent_run_id, ended_at, "SUCCESS")
        repository.finish_pipeline_run(pipeline_run_id, ended_at, "SUCCESS", len(mapped))
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        repository.insert_artifact({
            "artifact_type": "OBJ_FINDINGS_JSONL", "filename": source.name,
            "storage_path": str(source.resolve()), "sha256": digest,
        })
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return pipeline_run_id


def render_summary(stats: LoadStats, *, dry_run: bool) -> str:
    status = "READY" if stats.mapping_errors == 0 else "FAILED"
    return "\n".join([
        "PostgreSQL Load Dry Run" if dry_run else "PostgreSQL Load",
        "--------------------------------",
        f"Input findings: {stats.input_findings}",
        f"Mapped findings: {stats.mapped_findings}",
        f"Servers: {stats.servers}",
        f"Vulnerabilities: {stats.vulnerabilities}",
        f"Applications available: {stats.applications_available}",
        f"Applications unresolved: {stats.applications_unresolved}",
        f"Mapping errors: {stats.mapping_errors}",
        f"Warnings: {stats.warnings}",
        f"Status: {status}",
        "--------------------------------",
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        mapped, stats, messages = prepare_input(args.input)
    except (FileNotFoundError, JsonlInputError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(render_summary(stats, dry_run=args.dry_run))
    for message in messages:
        print(f"WARNING: {message}", file=sys.stderr)
    if stats.mapping_errors:
        return 1
    if args.dry_run:
        return 0
    connection = connect()
    try:
        pipeline_run_id = load_transaction(connection, mapped, args.input)
    finally:
        connection.close()
    print(f"Pipeline run: {pipeline_run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
