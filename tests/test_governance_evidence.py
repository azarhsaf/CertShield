from app.services.governance_evidence import (
    apply_governance_evidence,
    governance_control_key,
)


def _item(severity: str = "Medium") -> dict:
    return {
        "category": "Backup and Recovery",
        "title": "CA backup and recovery should be documented",
        "status": "Not Assessed",
        "display_status": "Not Assessed",
        "severity": severity,
        "affected_object": "TEST-CA",
        "evidence": {},
        "confidence": "low",
        "data_source": "operator evidence",
        "not_assessed_reason": "No evidence entered.",
    }


def test_implemented_manual_evidence_closes_gap():
    item = _item()
    key = governance_control_key(
        item["category"],
        item["affected_object"],
        item["title"],
    )

    result = apply_governance_evidence(
        [item],
        {
            key: {
                "state": "implemented",
                "owner": "PKI Operations",
                "details": "Recovery test completed.",
            }
        },
    )[0]

    assert result["status"] == "Pass"
    assert result["manual_control"] is True
    assert result["not_assessed_reason"] is None
    assert result["evidence"]["operator_evidence"]["owner"] == (
        "PKI Operations"
    )


def test_partial_manual_evidence_requires_attention():
    item = _item()
    key = governance_control_key(
        item["category"],
        item["affected_object"],
        item["title"],
    )

    result = apply_governance_evidence(
        [item],
        {key: {"state": "partial"}},
    )[0]

    assert result["status"] == "Warning"


def test_unimplemented_high_control_becomes_high_risk():
    item = _item("High")
    key = governance_control_key(
        item["category"],
        item["affected_object"],
        item["title"],
    )

    result = apply_governance_evidence(
        [item],
        {key: {"state": "not_implemented"}},
    )[0]

    assert result["status"] == "Fail"
