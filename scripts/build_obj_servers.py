#!/usr/bin/env python3
"""Build scoped obj_servers and Application-Server relations from an APM CSV."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.application_parser import extract_finding_auids
from src.server_parser import REQUIRED_SERVER_COLUMNS, SERVER_COLUMN_MAPPING, parse_servers


def _load_apm_csv(path: Path) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(f"APM CSV file not found: {path}")
    try:
        return pd.read_csv(path, dtype=object, keep_default_na=False)
    except (OSError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise ValueError(f"Unable to read APM CSV {path}: {exc}") from exc


def write_outputs(input_path: Path, findings_path: Path, output_dir: Path):
    target_auids, finding_stats = extract_finding_auids(findings_path)
    frame = _load_apm_csv(input_path)
    servers, relations, anomalies, server_stats = parse_servers(frame, target_auids)

    output_dir.mkdir(parents=True, exist_ok=True)
    servers_path = output_dir / "obj_servers.jsonl"
    relations_path = output_dir / "application_server_relations.jsonl"
    anomalies_path = output_dir / "server_anomalies.json"
    analysis_path = output_dir / "server_analysis.json"
    servers_path.write_text(
        "".join(server.model_dump_json() + "\n" for server in servers), encoding="utf-8"
    )
    relations_path.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in relations),
        encoding="utf-8",
    )
    anomalies_path.write_text(
        json.dumps([item.model_dump() for item in anomalies], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    report = {
        **finding_stats,
        **server_stats,
        "source_file": str(input_path.resolve()),
        "findings_file": str(findings_path.resolve()),
        "required_columns": REQUIRED_SERVER_COLUMNS,
        "mapping": SERVER_COLUMN_MAPPING,
        "unmapped_apm_fields": {
            "sensitive": "NO APM SOURCE CONFIRMED",
            "authenticated_scan": "NO APM SOURCE CONFIRMED",
            "Asset ID": "TO_VALIDATE: no existing source identifier contract",
        },
        "artifacts": {
            "obj_servers": str(servers_path.resolve()),
            "relations": str(relations_path.resolve()),
            "anomalies": str(anomalies_path.resolve()),
            "analysis": str(analysis_path.resolve()),
        },
    }
    analysis_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return servers_path, relations_path, anomalies_path, analysis_path, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        paths = write_outputs(args.input, args.findings, args.output_dir)
    except (FileNotFoundError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(paths[4], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

