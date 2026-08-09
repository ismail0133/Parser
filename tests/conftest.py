from pathlib import Path

import pandas as pd
import pytest

from src.loaders.finding_loader import EXPECTED_COLUMNS


def synthetic_row(**overrides):
    row = {column: "" for column in EXPECTED_COLUMNS}
    row.update({
        "Month": "May 2026",
        "REM_KEY_ID": "1004-s00v19981544",
        "HOSTNAME": "s00v19981544",
        "OPERATING_SYSTEM": "RHEL_9.6",
        "AFFECTED_PLATFORMS": "Red Hat Enterprise Linux 9.6",
        "AUID": "AP10426",
        "ENVIRONMENT": "PRODUCTION",
        "CODE_APP": "AP99999",
        "CVE": "CVE-2026-1234",
        "title": "Synthetic vulnerability",
        "PRIORITY": "PR1",
        "AFFECTED_PRODUCTS_REVIEWED": "openssl",
        "PRODUCT": "RHEL",
        "XTRACT_PATH": "/appli/test/component",
        "ABSOLUTE_FIRST_FOUND_DATE": "2026-05-01",
        "FIRST_FOUND_DATE": "2026-05-02",
        "LAST_FOUND_DATE": "2026-05-13",
        "AGE": "12",
        "SLA": "",
        "SOLUTION_LINKS": "https://example.invalid/fix",
        "Legacy APP ID": "ABC",
        "Application Name": "Synthetic App",
        "AppSec Profile": "P4",
        "IT Sub Cluster": "Banking",
        "PROPOSED_ACTION": "Patch",
        "SEVERITY_LEVEL": "Very High",
        "Action Plan": "Patch during maintenance",
        "ETA": "2026-06-30",
    })
    row.update(overrides)
    return row


@pytest.fixture
def csv_factory(tmp_path: Path):
    def create(rows=None, columns=None, encoding="utf-8-sig"):
        rows = rows or [synthetic_row()]
        frame = pd.DataFrame(rows, columns=columns or EXPECTED_COLUMNS)
        path = tmp_path / "findings.csv"
        frame.to_csv(path, index=False, encoding=encoding)
        return path
    return create
