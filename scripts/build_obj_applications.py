#!/usr/bin/env python3
"""Build scoped obj_applications.jsonl from an APM CSV and obj_findings."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.application_parser import (
    APPLICATION_COLUMN_MAPPING,
    OPTIONAL_APPLICATION_COLUMNS,
    REQUIRED_APPLICATION_COLUMNS,
    extract_finding_auids,
    parse_applications,
)


def _load_apm_csv(path: Path) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(f"APM CSV file not found: {path}")
    try:
        frame = pd.read_csv(path, dtype=object, keep_default_na=False)
    except (OSError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise ValueError(f"Unable to read APM CSV {path}: {exc}") from exc
    return frame


def write_outputs(input_path: Path, findings_path: Path, output_dir: Path):
    target_auids, finding_stats = extract_finding_auids(findings_path)
    frame = _load_apm_csv(input_path)
    applications, anomalies, application_stats = parse_applications(frame, target_auids)

    output_dir.mkdir(parents=True, exist_ok=True)
    applications_path = output_dir / "obj_applications.jsonl"
    anomalies_path = output_dir / "application_anomalies.json"
    analysis_path = output_dir / "application_analysis.json"
    applications_path.write_text(
        "".join(application.model_dump_json() + "\n" for application in applications),
        encoding="utf-8",
    )
    anomalies_path.write_text(
        json.dumps([item.model_dump() for item in anomalies], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    report = {
        **finding_stats,
        **application_stats,
        "source_file": str(input_path.resolve()),
        "findings_file": str(findings_path.resolve()),
        "required_columns": REQUIRED_APPLICATION_COLUMNS,
        "optional_columns": OPTIONAL_APPLICATION_COLUMNS,
        "mapping": APPLICATION_COLUMN_MAPPING,
        "artifacts": {
            "obj_applications": str(applications_path.resolve()),
            "anomalies": str(anomalies_path.resolve()),
            "analysis": str(analysis_path.resolve()),
        },
    }
    analysis_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return applications_path, anomalies_path, analysis_path, report


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
    print(json.dumps(paths[3], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
