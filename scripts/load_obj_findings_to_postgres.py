#!/usr/bin/env python3
"""Validate, map, and transactionally load Applications and enriched Findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import UUID, uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cleaning.finding_cleaner import normalize_string
from src.persistence.database import connect
from src.persistence.finding_mapper import map_obj_application, map_obj_finding
from src.persistence.postgres_repository import PostgresFindingRepository


@dataclass
class LoadStats:
    total_applications: int = 0
    total_findings: int = 0
    applications_mapped: int = 0
    applications_errors: int = 0
    findings_mapped: int = 0
    findings_errors: int = 0
    findings_with_auid: int = 0
    findings_without_auid: int = 0
    application_fk_resolved: int = 0
    application_fk_unresolved: int = 0
    servers_detected: int = 0
    vulnerabilities_detected: int = 0
    anomalies_detected: int = 0
    input_findings: int = 0
    output_findings: int = 0
    input_equals_output: bool = False
    mapping_errors: int = 0
    warnings: int = 0

    @property
    def status(self) -> str:
        return "READY" if self.mapping_errors == 0 and self.input_equals_output else "FAILED"


class JsonlInputError(ValueError):
    pass


def read_jsonl(path: Path, object_name: str = "object") -> Iterable[tuple[int, dict[str, Any]]]:
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
                raise JsonlInputError(f"Line {line_no}: {object_name} must be a JSON object")
            yield line_no, payload


def _normalized_auid(value: Any) -> str | None:
    normalized = normalize_string(value)
    return normalized.upper() if normalized is not None else None


def prepare_inputs(applications_path: Path, findings_path: Path):
    applications: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stats = LoadStats()
    messages: list[str] = []
    application_auids: set[str] = set()
    for line_no, payload in read_jsonl(applications_path, "obj_application"):
        stats.total_applications += 1
        try:
            mapped = map_obj_application(payload)
            json.dumps(mapped, ensure_ascii=False)
            if mapped["auid"] in application_auids:
                raise ValueError(f"duplicate obj_application.auid: {mapped['auid']}")
        except (TypeError, ValueError) as exc:
            stats.applications_errors += 1
            messages.append(f"Application line {line_no}: {exc}")
            continue
        application_auids.add(mapped["auid"])
        applications.append(mapped)
        stats.applications_mapped += 1

    seen_servers: set[str] = set()
    seen_vulnerabilities: set[str] = set()
    for line_no, payload in read_jsonl(findings_path, "obj_finding"):
        stats.total_findings += 1
        stats.input_findings += 1
        try:
            relational = map_obj_finding(payload)
            json.dumps(relational, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            stats.findings_errors += 1
            messages.append(f"Finding line {line_no}: {exc}")
            continue
        findings.append(relational)
        stats.findings_mapped += 1
        auid = _normalized_auid(relational["finding"].get("application_auid"))
        if auid is None:
            stats.findings_without_auid += 1
        else:
            stats.findings_with_auid += 1
            if auid in application_auids:
                stats.application_fk_resolved += 1
            else:
                stats.application_fk_unresolved += 1
                stats.anomalies_detected += 1
                stats.warnings += 1
                messages.append(f"Finding line {line_no}: UNRESOLVED_APPLICATION_AUID")
        if relational["server"] is not None:
            seen_servers.add(json.dumps(relational["server"], sort_keys=True, ensure_ascii=False))
        if relational["vulnerability"] is not None:
            seen_vulnerabilities.add(json.dumps(relational["vulnerability"], sort_keys=True, ensure_ascii=False))
    stats.servers_detected = len(seen_servers)
    stats.vulnerabilities_detected = len(seen_vulnerabilities)
    stats.output_findings = len(findings)
    stats.input_equals_output = stats.input_findings == stats.output_findings
    stats.mapping_errors = stats.applications_errors + stats.findings_errors
    if stats.input_findings == 0:
        stats.warnings += 1
        messages.append("Input contains no findings")
    return applications, findings, stats, messages


def load_transaction(connection: Any, applications: list[dict[str, Any]], findings: list[dict[str, Any]],
                     applications_source: Path, findings_source: Path, run_id: UUID | None = None) -> UUID:
    repository = PostgresFindingRepository(connection)
    pipeline_run_id = run_id or uuid4()
    now = datetime.now(timezone.utc)
    server_ids: dict[str, Any] = {}
    application_ids: dict[str, Any] = {}
    try:
        repository.create_pipeline_run({
            "pipeline_run_id": pipeline_run_id, "started_at": now, "ended_at": None,
            "run_status": "RUNNING", "source_filename": findings_source.name,
            "input_rows": len(findings), "output_findings": 0, "error_count": 0, "warning_count": 0,
        })
        agent_id = repository.get_or_create_agent("PARSER")
        agent_run_id = repository.create_agent_run({
            "pipeline_run_id": pipeline_run_id, "agent_id": agent_id, "attempt_no": 1,
            "started_at": now, "ended_at": None, "run_status": "RUNNING",
            "feedback_type": None, "feedback_message": None,
        })
        for application in applications:
            application_ids[application["auid"]] = repository.get_or_create_application(application)
        for relational in findings:
            finding = dict(relational["finding"])
            auid = _normalized_auid(finding.get("application_auid"))
            application_id = application_ids.get(auid) if auid is not None else None
            server_id = None
            if relational["server"] is not None:
                key = json.dumps(relational["server"], sort_keys=True, ensure_ascii=False)
                if key not in server_ids:
                    server_ids[key] = repository.create_server(relational["server"])
                server_id = server_ids[key]
            vulnerability_id = None
            if relational["vulnerability"] is not None:
                vulnerability_id = repository.get_or_create_vulnerability(relational["vulnerability"])
            finding.update({"pipeline_run_id": pipeline_run_id, "application_id": application_id,
                            "server_id": server_id, "vulnerability_id": vulnerability_id})
            finding_id = repository.insert_finding(finding)
            if auid is not None and application_id is None:
                repository.insert_anomaly({
                    "pipeline_run_id": pipeline_run_id, "agent_run_id": agent_run_id,
                    "finding_id": finding_id, "anomaly_level": "WARNING",
                    "code": "UNRESOLVED_APPLICATION_AUID",
                    "message": "Finding AUID has no canonical Application.", "details": {"auid": auid},
                })
        ended_at = datetime.now(timezone.utc)
        repository.finish_agent_run(agent_run_id, ended_at, "SUCCESS")
        repository.finish_pipeline_run(pipeline_run_id, ended_at, "SUCCESS", len(findings))
        for artifact_type, source in (("OBJ_APPLICATIONS_JSONL", applications_source),
                                      ("OBJ_FINDINGS_ENRICHED_JSONL", findings_source)):
            repository.insert_artifact({
                "artifact_type": artifact_type, "filename": source.name,
                "storage_path": str(source.resolve()),
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            })
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return pipeline_run_id


def render_summary(stats: LoadStats, *, dry_run: bool) -> str:
    values = asdict(stats)
    values["status"] = stats.status
    title = "PostgreSQL Load Dry Run" if dry_run else "PostgreSQL Load"
    return "\n".join([title, "--------------------------------"] + [
        f"{name}: {str(value).lower() if isinstance(value, bool) else value}"
        for name, value in values.items()
    ] + ["--------------------------------"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--applications", required=True, type=Path)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        applications, findings, stats, messages = prepare_inputs(args.applications, args.findings)
    except (FileNotFoundError, JsonlInputError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(render_summary(stats, dry_run=args.dry_run))
    for message in messages:
        print(f"WARNING: {message}", file=sys.stderr)
    if stats.status == "FAILED":
        return 1
    if args.dry_run:
        return 0
    connection = connect()
    try:
        pipeline_run_id = load_transaction(connection, applications, findings,
                                           args.applications, args.findings)
    finally:
        connection.close()
    print(f"Pipeline run: {pipeline_run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
