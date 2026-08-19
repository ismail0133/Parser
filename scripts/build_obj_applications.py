#!/usr/bin/env python3
"""Build canonical obj_applications.jsonl from the RAW Finding CSV."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.application_parser import (
    APPLICATION_COLUMN_MAPPING,
    analyze_finding_coverage,
    parse_applications,
)
from src.loaders.finding_loader import load_findings


def write_outputs(input_path: Path, output_dir: Path, findings_path: Path | None = None):
    frame = load_findings(input_path)
    print(f"df.shape = {frame.shape}")
    print(f"df.columns.tolist() = {frame.columns.tolist()}")
    applications, anomalies, stats = parse_applications(frame)
    coverage = None
    if findings_path is not None:
        if not findings_path.is_file():
            raise FileNotFoundError(f"obj_findings file not found: {findings_path}")
        coverage = analyze_finding_coverage(findings_path, applications)
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
        **stats,
        "source_file": str(input_path.resolve()),
        "source_shape": list(frame.shape),
        "source_columns": frame.columns.tolist(),
        "application_columns": ["AUID", *APPLICATION_COLUMN_MAPPING],
        "finding_coverage": coverage,
        "artifacts": {
            "obj_applications": str(applications_path.resolve()),
            "anomalies": str(anomalies_path.resolve()),
        },
    }
    analysis_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return applications_path, anomalies_path, analysis_path, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--findings", type=Path)
    args = parser.parse_args(argv)
    try:
        paths = write_outputs(args.input, args.output_dir, args.findings)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(paths[3], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
