from src.parser import parse_findings
from tests.conftest import synthetic_row


def test_unique_id_is_cve_and_duplicates_are_allowed(csv_factory):
    rows = [
        synthetic_row(REM_KEY_ID="one", CVE="CVE-2026-12345"),
        synthetic_row(REM_KEY_ID="two", CVE="CVE-2026-12345"),
    ]
    findings, anomalies, _ = parse_findings(csv_factory(rows))
    assert [item.unique_id for item in findings] == ["CVE-2026-12345", "CVE-2026-12345"]
    assert not any("UNIQUE" in item.error_type for item in anomalies)


def test_missing_cve_has_no_unique_id_fallback(csv_factory):
    findings, _, _ = parse_findings(csv_factory([synthetic_row(CVE=None)]))
    assert findings[0].cve is None
    assert findings[0].unique_id is None


def test_remediation_id_present_is_copied(csv_factory):
    findings, _, _ = parse_findings(csv_factory([synthetic_row(REM_KEY_ID="rem-1")]))
    assert findings[0].remediation_id == "rem-1"


def test_missing_remediation_id_is_none_with_non_blocking_control(csv_factory):
    findings, anomalies, stats = parse_findings(csv_factory([synthetic_row(REM_KEY_ID=None)]))
    assert findings[0].remediation_id is None
    control = [item for item in anomalies if item.error_type == "MISSING_REMEDIATION_ID"]
    assert len(control) == 1 and control[0].severity == "WARNING"
    assert stats["error_count"] == 0


def test_proposed_owner_is_preserved_without_routing(csv_factory):
    findings, _, _ = parse_findings(csv_factory([
        synthetic_row(**{"Proposed Owner": "Infrastructure Team"}),
        synthetic_row(REM_KEY_ID="two", **{"Proposed Owner": None}),
    ]))
    assert findings[0].ownership == "Infrastructure Team"
    assert findings[1].ownership is None
    assert findings[0].ownership not in {"APS", "ADM"}


def test_strategy_type_remains_analyst_responsibility(csv_factory):
    findings, _, _ = parse_findings(csv_factory([
        synthetic_row(PROPOSED_ACTION="Patch", **{"Action Plan": "Upgrade package"})
    ]))
    assert findings[0].remediation_strategy.strategy_type is None
