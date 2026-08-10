import pandas as pd
import pytest

from src.cleaning.finding_cleaner import clean_findings
from src.loaders.finding_loader import EXPECTED_COLUMNS, FindingSchemaError, load_findings


REAL_RAW_COLUMNS = [
    "Month", "REM_KEY_ID", "STATUS_REM", "HOSTNAME", "OPERATING_SYSTEM",
    "AFFECTED_PLATFORMS", "AUID", "ENVIRONMENT", "CODE_APP", "CVE", "title",
    "PRIORITY", "AFFECTED_PRODUCTS_REVIEWED", "PRODUCT", "XTRACT_PATH",
    "ABSOLUTE_FIRST_FOUND_DATE", "FIRST_FOUND_DATE", "LAST_FOUND_DATE", "AGE",
    "SLA", "SOLUTION_LINKS", "Legacy APP ID", "Application Name", "AppSec Profile",
    "Business Lines", "IT Sub Cluster", "Production Domain Manager",
    "Production Manager", "SEVERITY_LEVEL", "PROPOSED_ACTION", "Proposed Owner",
    "KRI RAS 9", "Action Plan", "ETA",
]


def test_loader_reads_34_columns_and_limit(csv_factory):
    path = csv_factory()
    frame = load_findings(path, limit=1)
    assert frame.shape == (1, 34)
    assert frame.columns.tolist() == EXPECTED_COLUMNS
    assert EXPECTED_COLUMNS == REAL_RAW_COLUMNS


def test_schema_rejects_missing_column(csv_factory):
    path = csv_factory(columns=EXPECTED_COLUMNS[:-1])
    with pytest.raises(FindingSchemaError, match="expected 34"):
        load_findings(path)


def test_null_cleaning():
    frame = pd.DataFrame({"a": ["  value  ", "NULL", "null", "N/A", ""]})
    assert clean_findings(frame)["a"].tolist() == ["value", None, None, None, None]
