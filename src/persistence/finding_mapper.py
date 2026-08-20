"""Pure mapping from Parser obj_finding JSON to relational row dictionaries."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from src.cleaning.finding_cleaner import normalize_string


APPLICATION_FIELDS = (
    "auid", "code_app", "trigram", "application_name", "appsec", "business_line",
    "production_domain_manager", "production_manager",
)


def _object(value: Any, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a JSON object")
    return value


def map_obj_application(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Map one canonical obj_application without deriving or dropping fields."""
    if not isinstance(payload, Mapping):
        raise ValueError("obj_application must be a JSON object")
    auid = normalize_string(payload.get("auid"))
    if auid is None:
        raise ValueError("obj_application.auid is required")
    return {
        field: auid.upper() if field == "auid" else payload.get(field)
        for field in APPLICATION_FIELDS
    }


def map_obj_finding(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Map one real Parser Finding payload without deriving new business data."""
    if not isinstance(payload, Mapping):
        raise ValueError("obj_finding must be a JSON object")
    source = deepcopy(dict(payload))
    server = _object(source.get("server"), "server")
    application = _object(source.get("application"), "application")
    cve_detail = _object(source.get("cve_detail"), "cve_detail")
    strategy = _object(source.get("remediation_strategy"), "remediation_strategy")

    hostname = source.get("hostname")
    server_row = None
    if hostname is not None or any(server.get(key) is not None for key in (
        "os_name", "os_version", "environment", "environment_detail",
        "sensitive", "authenticated_scan",
    )):
        server_row = {
            "hostname": hostname,
            "operating_system": None,
            "os_name": server.get("os_name"),
            "os_version": server.get("os_version"),
            "environment": server.get("environment"),
            "environment_detail": server.get("environment_detail"),
            "sensitive": server.get("sensitive"),
            "authenticated_scan": server.get("authenticated_scan"),
        }

    cve = source.get("cve")
    vulnerability_row = None
    if cve is not None or cve_detail.get("title") is not None or source.get("severity_level") is not None:
        vulnerability_row = {
            "cve_code": cve,
            "title": cve_detail.get("title"),
            "description": None,
            "severity_level": source.get("severity_level"),
            "cvss_score": None,
        }

    finding_row = {
        "source_unique_id": source.get("unique_id"),
        "remediation_id": source.get("remediation_id"),
        "application_auid": application.get("auid"),
        "as_of_date": source.get("as_of_date"),
        "absolute_first_found_date": source.get("first_detection"),
        "last_found_date": source.get("last_detection"),
        "age_days": source.get("age"),
        "sla_days": source.get("sla"),
        "overdue": source.get("overdue"),
        "priority": source.get("priority"),
        "affected_component": source.get("affected_component"),
        "product": source.get("affected_product"),
        "extract_path": source.get("target"),
        "severity_level": source.get("severity_level"),
        "business_line": source.get("business_line"),
        "proposed_action": source.get("proposed_action"),
        "ownership": source.get("ownership"),
        "false_positive": source.get("false_positive"),
        "false_positive_to_confirm": source.get("false_positive_to_confirm"),
        "eta": source.get("eta"),
        "strategy_type": strategy.get("strategy_type"),
        "strategy_description": strategy.get("description"),
        "solution_links": cve_detail.get("solution_links"),
        "source_payload": source,
    }
    return {
        "server": server_row,
        "vulnerability": vulnerability_row,
        "finding": finding_row,
    }
