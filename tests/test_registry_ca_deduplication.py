from app.services.assessment_registry import _best_practice_records


def _practice(title: str) -> dict:
    return {
        "category": "Root CA",
        "title": title,
        "status": "Not Assessed",
        "display_status": "Not Assessed",
        "severity": "Medium",
        "affected_object": "ROOT-CA-01",
        "confidence": "low",
        "data_source": "collector",
        "evidence": {},
        "recommendation": "Collect evidence.",
    }


def test_registry_skips_duplicate_ca_checks():
    best_practices = {
        "items": [
            _practice("CA auditing should be enabled"),
            _practice(
                "Root CA key protection should be known and appropriate"
            ),
            _practice(
                "Issuing CA key protection should be known and appropriate"
            ),
            _practice("Root CA should be offline"),
        ]
    }

    records = _best_practice_records(best_practices, {})
    titles = {record["title"] for record in records}

    assert "CA auditing should be enabled" not in titles
    assert (
        "Root CA key protection should be known and appropriate"
        not in titles
    )
    assert (
        "Issuing CA key protection should be known and appropriate"
        not in titles
    )
    assert "Root CA should be offline" in titles
