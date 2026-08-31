"""Build scoped obj_server records and Application-Server relations from APM."""

from __future__ import annotations

from collections import Counter
import re
from typing import Any

import pandas as pd

from src.cleaning.finding_cleaner import normalize_string
from src.models.server import ObjServer, ServerAnomaly


SERVER_COLUMN_MAPPING = {
    "Host": "hostname",
    "OS Build": "operating_system",
    "Environment": "environment",
}
REQUIRED_SERVER_COLUMNS = ["AUID", *SERVER_COLUMN_MAPPING]


def _normalized_series(series: pd.Series) -> pd.Series:
    return series.map(normalize_string)


def parse_os_build(value: Any) -> tuple[str | None, str | None]:
    """Conservatively split an OS build before its first digit-led token."""
    operating_system = normalize_string(value)
    if operating_system is None:
        return None, None
    version_start = re.search(r"(?<!\S)(?=\d)", operating_system)
    if version_start is None:
        return None, None
    os_name = operating_system[:version_start.start()].strip()
    os_version = operating_system[version_start.start():].strip()
    if not os_name or not os_version:
        return None, None
    return os_name, os_version


def parse_servers(
    frame: pd.DataFrame, target_auids: set[str]
) -> tuple[list[ObjServer], list[dict[str, str]], list[ServerAnomaly], dict[str, Any]]:
    """Build coherent distinct servers and their distinct scoped AUID relations."""
    missing_columns = [
        column for column in REQUIRED_SERVER_COLUMNS if column not in frame.columns
    ]
    if missing_columns:
        raise ValueError(f"Missing required APM CSV columns: {missing_columns}")

    normalized_auids = _normalized_series(frame["AUID"]).str.upper()
    scoped = frame.loc[normalized_auids.isin(target_auids)].copy()
    scoped["AUID"] = normalized_auids.loc[scoped.index]
    scoped["Host"] = _normalized_series(scoped["Host"])

    with_host = scoped.loc[scoped["Host"].notna()].copy()
    missing_host_count = len(scoped) - len(with_host)
    detected_relations = {
        (row["AUID"], row["Host"])
        for _, row in with_host[["AUID", "Host"]].iterrows()
    }

    servers: list[ObjServer] = []
    anomalies: list[ServerAnomaly] = []
    inconsistent_hosts: set[str] = set()
    conflict_counts: Counter[str] = Counter()
    for hostname, rows in with_host.groupby("Host", sort=True):
        data: dict[str, Any] = {"hostname": hostname}
        conflicts: list[tuple[str, int]] = []
        for source_column, target_field in SERVER_COLUMN_MAPPING.items():
            if target_field == "hostname":
                continue
            values = _normalized_series(rows[source_column]).dropna().unique()
            if len(values) > 1:
                conflicts.append((target_field, len(values)))
            else:
                data[target_field] = values[0] if len(values) == 1 else None
        if conflicts:
            inconsistent_hosts.add(hostname)
            for field, distinct_value_count in conflicts:
                conflict_counts[field] += 1
                anomalies.append(ServerAnomaly(
                    error_type="SERVER_CONFLICT",
                    hostname=hostname,
                    field=field,
                    distinct_value_count=distinct_value_count,
                ))
            continue
        data["os_name"], data["os_version"] = parse_os_build(
            data.get("operating_system")
        )
        servers.append(ObjServer.model_validate(data))

    if missing_host_count:
        anomalies.append(ServerAnomaly(
            error_type="MISSING_SERVER_HOSTNAME",
            hostname=None,
            field="hostname",
            distinct_value_count=0,
        ))

    generated_hosts = {server.hostname for server in servers}
    relations = [
        {"auid": auid, "hostname": hostname}
        for auid, hostname in sorted(detected_relations)
        if hostname in generated_hosts
    ]
    operating_system_populated = sum(
        server.operating_system is not None for server in servers
    )
    environment_populated = sum(server.environment is not None for server in servers)
    os_name_populated = sum(server.os_name is not None for server in servers)
    os_version_populated = sum(server.os_version is not None for server in servers)
    stats = {
        "total_apm_rows": len(frame),
        "matching_apm_rows": len(scoped),
        "rows_with_host": len(with_host),
        "rows_without_host": missing_host_count,
        "distinct_servers_detected": with_host["Host"].nunique(),
        "servers_generated": len(servers),
        "servers_with_operating_system": operating_system_populated,
        "servers_without_operating_system": len(servers) - operating_system_populated,
        "servers_with_os_name": os_name_populated,
        "servers_without_os_name": len(servers) - os_name_populated,
        "servers_with_os_version": os_version_populated,
        "servers_without_os_version": len(servers) - os_version_populated,
        "servers_with_environment": environment_populated,
        "servers_without_environment": len(servers) - environment_populated,
        "server_inconsistencies": len(inconsistent_hosts),
        "operating_system_inconsistencies": conflict_counts["operating_system"],
        "environment_inconsistencies": conflict_counts["environment"],
        "application_server_relations_detected": len(detected_relations),
        "application_server_relations_generated": len(relations),
        "distinct_applications_in_relations": len({item[0] for item in detected_relations}),
        "distinct_servers_in_relations": len({item[1] for item in detected_relations}),
        "input_output_consistency": (
            len(servers) + len(inconsistent_hosts) == with_host["Host"].nunique()
        ),
    }
    return servers, relations, anomalies, stats
