from types import SimpleNamespace

from app.services.assessment_registry import (
    _assurance,
    _best_practice_records,
    _record,
    registry_fingerprint,
)


def test_template_controls_are_not_scored_twice():
    best_practices = {
        "items": [
            {
                "category": "Templates",
                "title": (
                    "Avoid broad enrollment on "
                    "authentication templates"
                ),
                "status": "Fail",
                "display_status": "High Risk",
                "severity": "High",
                "affected_object": "ClientAuth",
                "evidence": {},
            },
            {
                "category": "Backup and Recovery",
                "title": (
                    "CA backup and recovery "
                    "should be documented"
                ),
                "status": "Not Assessed",
                "severity": "Medium",
                "affected_object": "ROOT-CA",
                "evidence": {},
            },
        ]
    }

    records = _best_practice_records(
        best_practices,
        {},
    )

    titles = {record["title"] for record in records}

    assert (
        "Avoid broad enrollment on authentication templates"
        not in titles
    )
    assert (
        "CA backup and recovery should be documented"
        in titles
    )


def test_repeated_same_risk_family_has_limited_deduction():
    records = [
        _record(
            object_type="health_check",
            object_name=f"CA-{number}",
            category="CA Health",
            title="CRL/CDP publication and freshness",
            status="Critical",
            severity="Critical",
            confidence="high",
            source="test",
            evidence={},
            recommendation="Fix CRL",
            acceptances={},
        )
        for number in range(1, 6)
    ]

    assurance = _assurance(records, {})

    assert assurance["score"] >= 70


def test_accepting_risk_cannot_lower_assurance_score():
    fingerprint = registry_fingerprint(
        "Key Protection",
        "ca",
        "ROOT-CA",
        "CA key protection status",
    )

    open_record = _record(
        object_type="ca",
        object_name="ROOT-CA",
        category="Key Protection",
        title="CA key protection status",
        status="High Risk",
        severity="High",
        confidence="high",
        source="test",
        evidence={},
        recommendation="Use HSM",
        acceptances={},
        fingerprint=fingerprint,
    )

    acceptance = SimpleNamespace(
        id=1,
        status="active",
        expiry_date="2099-01-01",
    )

    accepted_record = _record(
        object_type="ca",
        object_name="ROOT-CA",
        category="Key Protection",
        title="CA key protection status",
        status="High Risk",
        severity="High",
        confidence="high",
        source="test",
        evidence={},
        recommendation="Use HSM",
        acceptances={fingerprint: acceptance},
        fingerprint=fingerprint,
    )

    open_score = _assurance(
        [open_record],
        {},
    )["score"]

    accepted_score = _assurance(
        [accepted_record],
        {},
    )["score"]

    assert accepted_score >= open_score


def test_accepted_missing_evidence_is_still_missing_evidence():
    fingerprint = registry_fingerprint(
        "Best Practices",
        "best_practice",
        "ROOT-CA",
        "CA backup and recovery should be documented",
    )

    acceptance = SimpleNamespace(
        id=1,
        status="active",
        expiry_date="2099-01-01",
    )

    record = _record(
        object_type="best_practice",
        object_name="ROOT-CA",
        category="Best Practices",
        title="CA backup and recovery should be documented",
        status="Not Assessed",
        severity="Medium",
        confidence="low",
        source="operator evidence",
        evidence={},
        recommendation="Document recovery",
        acceptances={fingerprint: acceptance},
        fingerprint=fingerprint,
    )

    assert record["accepted_risk"] is True
    assert record["original_status"] == "Not Assessed"
