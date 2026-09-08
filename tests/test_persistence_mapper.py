import json

import pytest

from src.persistence.finding_mapper import map_obj_application, map_obj_finding, map_obj_server
from src.models.application import ObjApplication
from src.models.server import ObjServer


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
    assert "application" not in result
    assert result["finding"]["absolute_first_found_date"] == "2026-05-01"
    assert result["finding"]["false_positive"] is False
    assert result["finding"]["strategy_type"] is None
    assert result["finding"]["source_payload"] == source
    assert result["finding"]["source_payload"] is not source


def test_real_obj_server_jsonl_contract_maps_to_postgres_columns():
    source = ObjServer(
        hostname=" server01 ",
        operating_system="Red Hat Enterprise Linux 9.6",
        os_name="Red Hat Enterprise Linux",
        os_version="9.6",
        environment="PROD",
    )

    result = map_obj_server(json.loads(source.model_dump_json()))

    assert result == {
        "hostname": "server01",
        "operating_system": "Red Hat Enterprise Linux 9.6",
        "os_name": "Red Hat Enterprise Linux",
        "os_version": "9.6",
        "environment": "PROD",
        "environment_detail": None,
        "sensitive": None,
        "authenticated_scan": None,
    }


@pytest.mark.parametrize("hostname", [None, "", "   "])
def test_obj_server_without_usable_hostname_is_rejected(hostname):
    with pytest.raises(ValueError, match="MISSING_SERVER_HOSTNAME"):
        map_obj_server({"hostname": hostname})


@pytest.mark.parametrize("hostname", [None, "", "   "])
def test_finding_without_usable_hostname_does_not_create_server(hostname):
    result = map_obj_finding(complete_finding(hostname=hostname))

    assert result["server"] is None


def test_finding_server_keeps_normalized_environment_and_kri_fields():
    result = map_obj_finding(complete_finding(
        hostname=" server01 ",
        server={
            "os_name": "Finding OS",
            "os_version": "1",
            "environment": "PRODUCTION",
            "environment_detail": "PRE-PRODUCTION",
            "sensitive": True,
            "authenticated_scan": False,
        },
    ))

    assert result["server"] == {
        "hostname": "server01",
        "operating_system": None,
        "os_name": "Finding OS",
        "os_version": "1",
        "environment": "PRODUCTION",
        "environment_detail": "PRE-PRODUCTION",
        "sensitive": True,
        "authenticated_scan": False,
    }


def test_application_auid_is_only_a_finding_reference():
    result = map_obj_finding(complete_finding(application={"auid": "AP10426"}))
    assert result["finding"]["application_auid"] == "AP10426"


def test_maps_real_obj_application_and_translates_name():
    source = ObjApplication(
        auid="AP10426",
        trigram="ABC",
        name="App",
        business_line="Retail",
        appsec="P4",
        vital="GROUPE",
        continuity_level="HIGH",
        application_manager="Application Manager",
        domain_manager="Domain Manager",
        production_manager="Production Manager",
        production_domain_manager="Production Domain Manager",
    ).model_dump()

    assert map_obj_application(source) == {
        "auid": "AP10426",
        "code_app": None,
        "trigram": "ABC",
        "application_name": "App",
        "appsec": "P4",
        "business_line": "Retail",
        "vital": "GROUPE",
        "continuity_level": "HIGH",
        "application_manager": "Application Manager",
        "domain_manager": "Domain Manager",
        "production_domain_manager": "Production Domain Manager",
        "production_manager": "Production Manager",
    }


def test_application_name_legacy_key_remains_supported():
    result = map_obj_application({"auid": " ap10426 ", "application_name": "Legacy App"})

    assert result["auid"] == "AP10426"
    assert result["application_name"] == "Legacy App"


def test_canonical_name_takes_precedence_over_legacy_application_name():
    result = map_obj_application({
        "auid": "AP10426", "name": "Canonical App", "application_name": "Legacy App",
    })

    assert result["application_name"] == "Canonical App"


def test_application_business_fields_are_not_duplicated_in_finding_row():
    result = map_obj_finding(complete_finding())
    finding = result["finding"]
    assert finding["business_line"] == "Banking"
    assert "code_app" not in finding
    assert "production_domain_manager" not in finding
    assert "production_manager" not in finding
    assert "trigram" not in finding
    assert "application_name" not in finding
    assert "appsec" not in finding


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
