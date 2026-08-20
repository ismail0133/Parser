from src.persistence.finding_mapper import map_obj_finding


def complete_finding(**overrides):
    payload = {
        "unique_id": "CVE-2026-1234", "remediation_id": "REM-1",
        "as_of_date": "2026-05-13", "hostname": "server01",
        "server": {"os_name": "RHEL", "os_version": "9.6", "environment": "PRODUCTION",
                   "environment_detail": "PRODUCTION", "sensitive": True, "authenticated_scan": True},
        "application": {"auid": "AP10426", "trigram": "ABC", "name": "App",
                        "appsec": "P4", "vital": None, "cis": None},
        "cve": "CVE-2026-1234",
        "cve_detail": {"title": "Issue", "solution_links": "https://example.invalid"},
        "priority": 1, "affected_component": "openssl", "affected_product": "RHEL",
        "target": "/target", "first_detection": "2026-05-01", "last_detection": "2026-05-13",
        "age": 12, "sla": 90, "overdue": False, "business_line": "Banking",
        "severity_level": "Very High", "proposed_action": "Patch", "ownership": "ADM",
        "remediation_strategy": {"description": "Patch", "strategy_type": None, "ownership_main": None},
        "false_positive": False, "false_positive_to_confirm": False, "eta": "2026-06-30",
    }
    payload.update(overrides)
    return payload


def test_maps_complete_finding_and_preserves_source_payload():
    source = complete_finding()
    result = map_obj_finding(source)
    assert result["server"]["os_name"] == "RHEL"
    assert result["vulnerability"]["cve_code"] == "CVE-2026-1234"
    assert result["application"]["application_name"] == "App"
    assert result["finding"]["absolute_first_found_date"] == "2026-05-01"
    assert result["finding"]["false_positive"] is False
    assert result["finding"]["strategy_type"] is None
    assert result["finding"]["source_payload"] == source
    assert result["finding"]["source_payload"] is not source


def test_application_with_only_auid_is_unresolved():
    result = map_obj_finding(complete_finding(application={"auid": "AP10426"}))
    assert result["application"] is None
    assert result["finding"]["application_auid"] == "AP10426"


def test_cve_absent_does_not_invent_code():
    result = map_obj_finding(complete_finding(unique_id=None, cve=None, severity_level=None,
                                              cve_detail={"title": None, "solution_links": None}))
    assert result["vulnerability"] is None
    assert result["finding"]["source_unique_id"] is None


def test_dates_booleans_and_false_positive_are_copied_without_conversion():
    result = map_obj_finding(complete_finding(
        as_of_date=None, overdue=None, false_positive=True,
        false_positive_to_confirm=True, eta=None,
    ))
    finding = result["finding"]
    assert finding["as_of_date"] is None
    assert finding["overdue"] is None
    assert finding["false_positive"] is True
    assert finding["false_positive_to_confirm"] is True
