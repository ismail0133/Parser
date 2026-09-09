import re
import unicodedata
from typing import Any

import pandas as pd


NULL_STRINGS = {"", "null", "n/a"}
FINDING_IDENTITY_COLUMNS = ("AUID", "CVE", "HOSTNAME", "REM_KEY_ID")
EXPORT_FOOTER_HEADINGS = {"filtres appliques", "filters applied"}
EXPORT_FILTER_EXPRESSION = re.compile(r"^.+\s+(?:n'est\s+pas|est)\s+.+$")


def _has_source_value(value: Any) -> bool:
    if value is None or value is pd.NA or bool(pd.isna(value)):
        return False
    return bool(str(value).strip())


def _normalize_export_text(value: Any) -> str:
    text = unicodedata.normalize("NFKD", str(value).strip())
    text = "".join(character for character in text if not unicodedata.combining(character))
    return " ".join(text.replace("’", "'").casefold().split())


def _source_row_values(row: pd.Series) -> list[str]:
    return [str(value).strip() for value in row if _has_source_value(value)]


def _has_finding_identity(row: pd.Series) -> bool:
    return any(_has_source_value(row.get(column)) for column in FINDING_IDENTITY_COLUMNS)


def _starts_export_footer(text: str) -> bool:
    return any(text == heading or text.startswith(f"{heading} ") for heading in EXPORT_FOOTER_HEADINGS)


def is_empty_source_row(row: pd.Series) -> bool:
    """Return True only when every RAW cell is missing or blank after trim."""
    for value in row:
        if value is None or value is pd.NA or bool(pd.isna(value)):
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return False
    return True


def is_export_footer_row(row: pd.Series) -> bool:
    """Identify an Excel filter/export footer row without a finding identity."""
    if _has_finding_identity(row):
        return False
    values = _source_row_values(row)
    if not values:
        return False
    text = _normalize_export_text(" ".join(values))
    return _starts_export_footer(text) or bool(EXPORT_FILTER_EXPRESSION.fullmatch(text))


def export_footer_row_mask(frame: pd.DataFrame) -> pd.Series:
    """Flag only footer metadata after the last row carrying a finding identity."""
    mask = pd.Series(False, index=frame.index, dtype=bool)
    last_identity_position = max(
        (
            position
            for position, (_, row) in enumerate(frame.iterrows())
            if _has_finding_identity(row)
        ),
        default=-1,
    )
    footer_started = False
    for position, (row_index, row) in enumerate(frame.iterrows()):
        if position <= last_identity_position:
            continue
        text = _normalize_export_text(" ".join(_source_row_values(row)))
        if not footer_started:
            footer_started = _starts_export_footer(text)
        if footer_started and is_export_footer_row(row):
            mask.loc[row_index] = True
    return mask


def normalize_string(value: Any) -> str | None:
    if value is None or value is pd.NA or bool(pd.isna(value)):
        return None
    text = str(value).strip()
    return None if text.casefold() in NULL_STRINGS else text


def clean_findings(frame: pd.DataFrame) -> pd.DataFrame:
    """Apply technical null and whitespace cleaning only."""
    cleaned = frame.copy()
    cleaned.columns = [str(column).strip() for column in cleaned.columns]
    for column in cleaned.columns:
        cleaned[column] = cleaned[column].map(normalize_string).astype(object)
        cleaned.loc[cleaned[column].isna(), column] = None
    cleaned.attrs.update(frame.attrs)
    return cleaned
