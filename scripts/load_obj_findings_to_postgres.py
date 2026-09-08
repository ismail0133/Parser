#!/usr/bin/env python3
"""Validate Parser artifacts and transactionally load PostgreSQL objects."""

from __future__ import annotations

import argparse
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
from src.models.finding import Anomaly
from src.models.parser_result import ParserResult
from src.persistence.artifact_mapper import (
    APPLICATION_SERVER_RELATIONS_JSONL,
    OBJ_APPLICATIONS_JSONL,
    OBJ_FINDINGS_ENRICHED_JSONL,
    OBJ_FINDINGS_JSONL,
    OBJ_SERVERS_JSONL,
    PARSER_ANOMALIES_JSON,
    PARSER_RESULT_JSON,
    ArtifactMetadataError,
    PreparedArtifact,
    artifact_matches_parser_declaration,
    prepare_artifact,
)
from src.persistence.database import connect
from src.persistence.finding_mapper import map_obj_application, map_obj_finding, map_obj_server
from src.persistence.parser_artifact_validator import (
    ParserArtifactValidationError,
    load_and_validate_parser_artifacts,
    map_anomaly_to_sql,
    validate_parser_data_consistency,
)
from src.persistence.postgres_repository import (
    SERVER_SOURCE_APM,
    SERVER_SOURCE_FINDING,
    PostgresFindingRepository,
)


@dataclass
class LoadStats:
    total_applications: int = 0
    total_findings: int = 0
    applications_mapped: int = 0
    applications_errors: int = 0
    findings_mapped: int = 0
    findings_errors: int = 0
    total_apm_servers: int = 0
    apm_servers_mapped: int = 0
    apm_servers_errors: int = 0
    server_conflicts: int = 0
    total_application_server_relations: int = 0
    application_server_relations_mapped: int = 0
    application_server_relations_errors: int = 0
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


def _normalized_hostname(value: Any) -> str | None:
    """Canonical hostname identity: trim technical whitespace, preserve case."""
    return normalize_string(value)


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


def prepare_server_inputs(
    servers_path: Path,
    relations_path: Path | None = None,
    *,
    application_auids: set[str] | None = None,
    stats: LoadStats | None = None,
    messages: list[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], LoadStats, list[str]]:
    """Validate APM Server artifacts and reject contradictory hostname records."""
    stats = stats or LoadStats()
    messages = messages if messages is not None else []
    candidates: dict[str, list[dict[str, Any]]] = {}
    for line_no, payload in read_jsonl(servers_path, "obj_server"):
        stats.total_apm_servers += 1
        try:
            mapped = map_obj_server(payload)
            json.dumps(mapped, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            stats.apm_servers_errors += 1
            stats.warnings += 1
            messages.append(f"Server line {line_no}: {exc}")
            continue
        candidates.setdefault(mapped["hostname"], []).append(mapped)

    servers: list[dict[str, Any]] = []
    for hostname, rows in candidates.items():
        merged: dict[str, Any] = {"hostname": hostname}
        conflicting_fields: list[str] = []
        for field in (
            "operating_system", "os_name", "os_version", "environment",
            "environment_detail", "sensitive", "authenticated_scan",
        ):
            values: list[Any] = []
            for row in rows:
                value = row.get(field)
                if value is not None and value not in values:
                    values.append(value)
            if len(values) > 1:
                conflicting_fields.append(field)
            merged[field] = values[0] if len(values) == 1 else None
        if conflicting_fields:
            stats.apm_servers_errors += 1
            stats.server_conflicts += 1
            stats.warnings += 1
            messages.append(
                f"SERVER_CONFLICT hostname={hostname} fields={','.join(conflicting_fields)}"
            )
            continue
        servers.append(merged)
        stats.apm_servers_mapped += 1

    relations: list[dict[str, str]] = []
    if relations_path is not None:
        valid_hosts = {server["hostname"] for server in servers}
        seen_relations: set[tuple[str, str]] = set()
        for line_no, payload in read_jsonl(relations_path, "application_server_relation"):
            stats.total_application_server_relations += 1
            try:
                auid = _normalized_auid(payload.get("auid"))
                hostname = _normalized_hostname(payload.get("hostname"))
                if auid is None:
                    raise ValueError("INVALID_APPLICATION_AUID")
                if hostname is None:
                    raise ValueError("MISSING_SERVER_HOSTNAME")
                if application_auids is not None and auid not in application_auids:
                    raise ValueError(f"UNRESOLVED_APPLICATION_AUID auid={auid}")
                if hostname not in valid_hosts:
                    raise ValueError(f"UNRESOLVED_SERVER_HOSTNAME hostname={hostname}")
            except (TypeError, ValueError) as exc:
                stats.application_server_relations_errors += 1
                stats.warnings += 1
                messages.append(f"Server relation line {line_no}: {exc}")
                continue
            key = (auid, hostname)
            if key in seen_relations:
                continue
            seen_relations.add(key)
            relations.append({"auid": auid, "hostname": hostname})
            stats.application_server_relations_mapped += 1

    stats.mapping_errors += (
        stats.apm_servers_errors + stats.application_server_relations_errors
    )
    return servers, relations, stats, messages


def prepare_artifact_inputs(
    applications_source: Path,
    findings_source: Path,
    parser_result_source: Path,
    parser_anomalies_source: Path,
    parser_result: ParserResult,
    *,
    servers_source: Path | None = None,
    server_relations_source: Path | None = None,
) -> list[PreparedArtifact]:
    """Prepare the complete set of files explicitly supplied to the loader."""
    findings_from_parser = artifact_matches_parser_declaration(
        findings_source,
        parser_result_path=parser_result_source,
        declared_path=parser_result.findings_artifact,
    )
    artifacts = [
        prepare_artifact(
            parser_result_source,
            PARSER_RESULT_JSON,
            produced_by_parser=True,
        ),
        prepare_artifact(
            parser_anomalies_source,
            PARSER_ANOMALIES_JSON,
            produced_by_parser=True,
        ),
        prepare_artifact(applications_source, OBJ_APPLICATIONS_JSONL),
        prepare_artifact(
            findings_source,
            OBJ_FINDINGS_JSONL if findings_from_parser else OBJ_FINDINGS_ENRICHED_JSONL,
            produced_by_parser=findings_from_parser,
        ),
    ]
    if servers_source is not None:
        artifacts.append(prepare_artifact(servers_source, OBJ_SERVERS_JSONL))
    if server_relations_source is not None:
        artifacts.append(prepare_artifact(
            server_relations_source,
            APPLICATION_SERVER_RELATIONS_JSONL,
        ))
    return artifacts


def load_transaction(
    connection: Any,
    applications: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    applications_source: Path,
    findings_source: Path,
    run_id: UUID | None = None,
    *,
    parser_result: ParserResult,
    parser_anomalies: list[Anomaly],
    artifacts: list[PreparedArtifact],
    servers: list[dict[str, Any]] | None = None,
    server_relations: list[dict[str, str]] | None = None,
) -> UUID:
    validate_parser_data_consistency(
        parser_result,
        parser_anomalies,
        output_findings_count=len(findings),
    )
    repository = PostgresFindingRepository(connection)
    pipeline_run_id = run_id or uuid4()
    now = datetime.now(timezone.utc)
    server_ids: dict[str, Any] = {}
    application_ids: dict[str, Any] = {}
    try:
        repository.create_pipeline_run({
            "pipeline_run_id": pipeline_run_id, "started_at": now, "ended_at": None,
            "run_status": parser_result.status,
            "source_filename": parser_result.input_file,
            "input_rows": parser_result.input_rows,
            "output_findings": parser_result.output_findings,
            "error_count": parser_result.errors,
            "warning_count": parser_result.warnings,
        })
        agent_id = repository.get_or_create_agent("PARSER")
        agent_run_id = repository.create_agent_run({
            "pipeline_run_id": pipeline_run_id, "agent_id": agent_id, "attempt_no": 1,
            "started_at": now, "ended_at": None, "run_status": parser_result.status,
            "feedback_type": None, "feedback_message": None,
        })
        for anomaly in parser_anomalies:
            repository.insert_anomaly(map_anomaly_to_sql(
                anomaly,
                pipeline_run_id=pipeline_run_id,
                agent_run_id=agent_run_id,
            ))
        for application in applications:
            application_ids[application["auid"]] = repository.get_or_create_application(application)
        for server in servers or []:
            server_ids[server["hostname"]] = repository.upsert_server(
                server, source=SERVER_SOURCE_APM
            )
        for relational in findings:
            finding = dict(relational["finding"])
            auid = _normalized_auid(finding.get("application_auid"))
            application_id = application_ids.get(auid) if auid is not None else None
            server_id = None
            if relational["server"] is not None:
                server_id = repository.upsert_server(
                    relational["server"], source=SERVER_SOURCE_FINDING
                )
                server_ids[relational["server"]["hostname"]] = server_id
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
        for relation in server_relations or []:
            repository.upsert_application_server_relation(
                application_ids[relation["auid"]], server_ids[relation["hostname"]]
            )
        ended_at = datetime.now(timezone.utc)
        repository.finish_agent_run(agent_run_id, ended_at, parser_result.status)
        repository.finish_pipeline_run(
            pipeline_run_id,
            ended_at,
            parser_result.status,
            parser_result.output_findings,
        )
        for artifact in artifacts:
            repository.insert_artifact(artifact.to_repository_row(
                pipeline_run_id=pipeline_run_id,
                parser_agent_run_id=agent_run_id,
            ))
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
    parser.add_argument("--parser-result", required=True, type=Path)
    parser.add_argument("--parser-anomalies", required=True, type=Path)
    parser.add_argument("--servers", type=Path)
    parser.add_argument("--application-server-relations", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.application_server_relations is not None and args.servers is None:
        parser.error("--application-server-relations requires --servers")
    try:
        applications, findings, stats, messages = prepare_inputs(args.applications, args.findings)
        parser_result, parser_anomalies = load_and_validate_parser_artifacts(
            args.parser_result,
            args.parser_anomalies,
            output_findings_count=len(findings),
        )
        servers: list[dict[str, Any]] = []
        server_relations: list[dict[str, str]] = []
        if args.servers is not None:
            servers, server_relations, stats, messages = prepare_server_inputs(
                args.servers,
                args.application_server_relations,
                application_auids={application["auid"] for application in applications},
                stats=stats,
                messages=messages,
            )
        artifacts = prepare_artifact_inputs(
            args.applications,
            args.findings,
            args.parser_result,
            args.parser_anomalies,
            parser_result,
            servers_source=args.servers,
            server_relations_source=args.application_server_relations,
        )
    except (
        FileNotFoundError,
        JsonlInputError,
        ParserArtifactValidationError,
        ArtifactMetadataError,
    ) as exc:
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
                                           args.applications, args.findings,
                                           parser_result=parser_result,
                                           parser_anomalies=parser_anomalies,
                                           artifacts=artifacts,
                                           servers=servers, server_relations=server_relations)
    finally:
        connection.close()
    print(f"Pipeline run: {pipeline_run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
