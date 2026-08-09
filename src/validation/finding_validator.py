import re
from typing import Any


# The exact policy remains TO_VALIDATE. This accepts the documented anonymized
# pattern and conventional numeric CVE identifiers without inferring severity.
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-(?:[0-9]{4,}|X{4})$", re.IGNORECASE)
AUID_PATTERN = re.compile(r"^AP[0-9]+$", re.IGNORECASE)


def validate_cve(value: str | None) -> bool:
    return bool(value and CVE_PATTERN.fullmatch(value))


def validate_auid(value: str | None) -> bool:
    return bool(value and AUID_PATTERN.fullmatch(value))


def validate_finding_payload(payload: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return field, error type, message triples for confirmed validations."""
    errors: list[tuple[str, str, str]] = []
    if payload.get("first_detection") is None:
        errors.append(("first_detection", "MISSING_REQUIRED_VALUE", "first_detection cannot be determined"))
    if not validate_cve(payload.get("cve")):
        errors.append(("CVE", "INVALID_CVE", "CVE does not match the supported documented structure"))
    if not validate_auid(payload.get("application", {}).get("auid")):
        errors.append(("AUID", "INVALID_OR_MISSING_AUID", "No valid application AUID is available"))
    return errors
