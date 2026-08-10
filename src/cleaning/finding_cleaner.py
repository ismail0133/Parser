from typing import Any

import pandas as pd


NULL_STRINGS = {"", "null", "n/a"}


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
