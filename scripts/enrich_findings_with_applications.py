#!/usr/bin/env python3
"""Enrich obj_findings JSONL from canonical obj_applications JSONL."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.enrichment.application_enricher import enrich_findings_jsonl


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--applications", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--anomalies", type=Path)
    args = parser.parse_args(argv)
    try:
        report = enrich_findings_jsonl(
            args.findings, args.applications, args.output,
            report_path=args.report, anomalies_path=args.anomalies,
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "SUCCESS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
