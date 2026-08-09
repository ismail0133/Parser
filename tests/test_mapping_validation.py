from src.mapping.finding_mapper import map_direct_fields, normalize_priority
from src.validation.finding_validator import validate_cve


def test_priority_mapping():
    assert [normalize_priority(f"PR{i}") for i in range(1, 5)] == [1, 2, 3, 4]
    assert normalize_priority("PR5") is None


def test_false_positive_and_aps_ingredients():
    mapped = map_direct_fields({"Action Plan": "False positive", "XTRACT_PATH": "/appli/x"})
    assert mapped["false_positive"] is True
    assert mapped["target"] == "/appli/x"


def test_cve_validation():
    assert validate_cve("CVE-2026-1234")
    assert validate_cve("CVE-2026-XXXX")
    assert not validate_cve("not-a-cve")
