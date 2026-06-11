from app.services.health_assessment import _score


def _item(status: str, category: str = "CRL Health") -> dict:
    return {
        "category": category,
        "title": "Health check",
        "status": status,
        "affected_object": "CA-01",
        "evidence": {},
        "recommendation": "",
        "impact": "operational",
    }


def test_health_coverage_never_exceeds_100_with_multiple_cas():
    items = (
        [_item("Healthy") for _ in range(13)]
        + [_item("Warning") for _ in range(5)]
        + [_item("Critical") for _ in range(4)]
    )

    _score_value, _status, _reasons, confidence, coverage, _factors = (
        _score(items)
    )

    assert coverage == 100
    assert confidence == "High"


def test_health_coverage_counts_not_assessed_checks():
    items = [
        _item("Healthy"),
        _item("Warning"),
        _item("Not Assessed"),
        _item("Unknown"),
    ]

    _score_value, _status, _reasons, confidence, coverage, _factors = (
        _score(items)
    )

    assert coverage == 50
    assert confidence == "Medium"


def test_not_configured_is_a_completed_assessment():
    items = [
        _item("Healthy"),
        _item("Not Configured", "OCSP Health"),
    ]

    _score_value, _status, _reasons, confidence, coverage, _factors = (
        _score(items)
    )

    assert coverage == 100
    assert confidence == "High"


def test_present_but_not_tested_is_not_complete_assessment():
    items = [
        _item("Healthy"),
        _item("Present / Not Tested", "AIA Health"),
    ]

    _score_value, _status, _reasons, confidence, coverage, _factors = (
        _score(items)
    )

    assert coverage == 50
    assert confidence == "Medium"
