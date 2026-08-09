from pathlib import Path

import pandas as pd


EXPECTED_COLUMNS = [
    "REPORTDATE - Month", "REM_KEY_ID", "STATUS_REM", "HOSTNAME",
    "OPERATING_SYSTEM", "AFFECTED_PLATFORMS", "AUID", "ENVIRONMENT",
    "CODE_APP", "CVE", "title", "PRIORITY", "AFFECTED_PRODUCTS_REVIEWED",
    "PRODUCT", "XTRACT_PATH", "ABSOLUTE_FIRST_FOUND_DATE", "FIRST_FOUND_DATE",
    "LAST_FOUND_DATE", "AGE", "SLA", "SOLUTION_LINKS", "Legacy APP ID",
    "Application Name", "AppSec Profile", "Business Lines", "IT Sub Cluster",
    "Production Domain Manager", "Production Manager", "PROPOSED_ACTION",
    "Colonne1", "SEVERITY_LEVEL", "KRI RAS 9", "Action Plan", "ETA",
]


class FindingLoadError(RuntimeError):
    """Raised when the CSV cannot be read safely."""


class FindingSchemaError(FindingLoadError):
    """Raised when the CSV schema differs from the documented 34 columns."""


def _validate_schema(columns: list[str]) -> None:
    missing = [column for column in EXPECTED_COLUMNS if column not in columns]
    unexpected = [column for column in columns if column not in EXPECTED_COLUMNS]
    if len(columns) != 34 or missing or unexpected:
        raise FindingSchemaError(
            "Invalid finding CSV schema: "
            f"expected 34 columns, got {len(columns)}; "
            f"missing={missing}; unexpected={unexpected}"
        )
    if columns != EXPECTED_COLUMNS:
        raise FindingSchemaError(
            "Invalid finding CSV column order. The documented 34-column order is required."
        )


def load_findings(path: str | Path, limit: int | None = None) -> pd.DataFrame:
    """Load a comma-separated finding file without applying business rules."""
    csv_path = Path(path)
    if not csv_path.is_file():
        raise FindingLoadError(f"Input CSV not found: {csv_path}")
    if limit is not None and limit < 0:
        raise FindingLoadError("limit must be a non-negative integer")

    errors: list[str] = []
    for encoding in ("utf-8-sig", "utf-8", "latin1"):
        try:
            frame = pd.read_csv(
                csv_path,
                sep=",",
                encoding=encoding,
                dtype=object,
                nrows=limit,
                keep_default_na=False,
                on_bad_lines="error",
            )
            frame.columns = [str(column).strip() for column in frame.columns]
            _validate_schema(frame.columns.tolist())
            frame.attrs["source_encoding"] = encoding
            return frame
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
        except FindingSchemaError:
            raise
        except (pd.errors.ParserError, OSError, ValueError) as exc:
            raise FindingLoadError(f"Unable to parse CSV {csv_path}: {exc}") from exc
    raise FindingLoadError(
        f"Unable to decode CSV {csv_path} with utf-8-sig, utf-8 or latin1: {errors}"
    )
