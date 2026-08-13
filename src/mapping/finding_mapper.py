from typing import Any

from src.cleaning.finding_cleaner import normalize_string


PRIORITY_MAPPING = {"PR1": 1, "PR2": 2, "PR3": 3, "PR4": 4}


def normalize_priority(value: Any) -> int | None:
    text = normalize_string(value)
    return PRIORITY_MAPPING.get(text.upper()) if text else None


def map_direct_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Map fields that need no date or business calculation."""
    action_plan = normalize_string(row.get("Action Plan"))
    folded_plan = action_plan.casefold() if action_plan else ""
    false_positive = folded_plan == "false positive"
    false_positive_to_confirm = "false positive to be confirmed" in folded_plan
    return {
        "remediation_id": normalize_string(row.get("REM_KEY_ID")),
        "hostname": normalize_string(row.get("HOSTNAME")),
        "cve": normalize_string(row.get("CVE")),
        "cve_title": normalize_string(row.get("title")),
        "priority": normalize_priority(row.get("PRIORITY")),
        "affected_component": normalize_string(row.get("AFFECTED_PRODUCTS_REVIEWED")),
        "affected_product": normalize_string(row.get("PRODUCT")),
        "target": normalize_string(row.get("XTRACT_PATH")),
        "solution_links": normalize_string(row.get("SOLUTION_LINKS")),
        "application_trigram": normalize_string(row.get("Legacy APP ID")),
        "application_name": normalize_string(row.get("Application Name")),
        "application_appsec": normalize_string(row.get("AppSec Profile")),
        "business_line": normalize_string(row.get("IT Sub Cluster")),
        "severity_level": normalize_string(row.get("SEVERITY_LEVEL")),
        "proposed_action": normalize_string(row.get("PROPOSED_ACTION")),
        "proposed_owner": normalize_string(row.get("Proposed Owner")),
        "action_plan": action_plan,
        "false_positive": false_positive,
        "false_positive_to_confirm": false_positive_to_confirm,
    }
