from dataclasses import dataclass, field
from typing import Any, Callable, Generic, TypeVar


T = TypeVar("T")
MAX_PARSE_ATTEMPTS = 3


@dataclass
class RetryAttempt:
    attempt_no: int
    errors_before: list[str]
    corrections_applied: list[str] = field(default_factory=list)
    errors_after: list[str] = field(default_factory=list)
    final_status: str = ""


def parse_with_retries(
    value: T,
    parse_and_validate: Callable[[T], tuple[Any, list[Any]]],
    apply_corrections: Callable[[T, list[Any]], tuple[T, list[str]] | None],
    *,
    max_attempts: int = MAX_PARSE_ATTEMPTS,
) -> tuple[Any, list[Any], list[RetryAttempt]]:
    """Retry only when a documented deterministic correction is applied."""
    current = value
    trace: list[RetryAttempt] = []
    result: Any = None
    anomalies: list[Any] = []
    for attempt_no in range(1, max_attempts + 1):
        result, anomalies = parse_and_validate(current)
        remediable = [
            item for item in anomalies
            if getattr(item, "classification", None) == "ERROR_REMEDIABLE"
        ]
        before = [getattr(item, "error_type", str(item)) for item in remediable]
        entry = RetryAttempt(attempt_no=attempt_no, errors_before=before)
        if not remediable:
            entry.errors_after = []
            entry.final_status = "SUCCESS" if not any(
                getattr(item, "severity", None) == "ERROR" for item in anomalies
            ) else "FAILED"
            trace.append(entry)
            break
        correction = apply_corrections(current, remediable)
        if correction is None:
            entry.errors_after = before
            entry.final_status = "FAILED"
            trace.append(entry)
            break
        current, applied = correction
        if not applied:
            entry.errors_after = before
            entry.final_status = "FAILED"
            trace.append(entry)
            break
        entry.corrections_applied = applied
        entry.errors_after = before
        entry.final_status = "RETRYING"
        trace.append(entry)
    else:
        trace[-1].final_status = "FAILED_AFTER_RETRIES"
    if trace and trace[-1].final_status == "RETRYING":
        trace[-1].final_status = "FAILED_AFTER_RETRIES"
    return result, anomalies, trace
