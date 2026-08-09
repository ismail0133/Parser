from collections.abc import Callable, Mapping
from typing import Any


ApplicationLookup = Mapping[str, Mapping[str, Any]] | Callable[[str], Mapping[str, Any] | None]


def enrich_with_application(
    finding: dict[str, Any], application_lookup: ApplicationLookup | None
) -> tuple[dict[str, Any], bool]:
    """Fill only missing application properties from an optional authoritative source."""
    if application_lookup is None:
        return finding, False
    auid = finding.get("application", {}).get("auid")
    if not auid:
        return finding, False
    application = (
        application_lookup(auid)
        if callable(application_lookup)
        else application_lookup.get(auid)
    )
    if not application:
        return finding, False
    target = finding.setdefault("application", {})
    for field in ("trigram", "name", "appsec", "vital", "cis"):
        if target.get(field) is None and application.get(field) is not None:
            target[field] = application[field]
    if finding.get("business_line") is None and application.get("business_line") is not None:
        finding["business_line"] = application["business_line"]
    return finding, True
