from app.models.entities import Finding
from app.services.posture_assessment import assess_pki_posture


def test_critical_findings_cap_posture_score():
    finding = Finding(
        severity="Critical",
        coverage_state="detected",
        title="Critical template exposure",
        esc_category="ESC1-like",
        affected_object="UserTemplate",
        remediation="Restrict enrollment",
        trigger_conditions="broad enrollment and requester-controlled subject",
        rationale="identity exposure",
        evidence_json={"risk_score": 92},
    )
    posture = assess_pki_posture(
        [finding],
        {"score": 95, "items": [], "limited_visibility": False},
        {"score": 95, "items": []},
        {"ESC1-like": "detected", "ESC2-like": "not_detected"},
        {"cas": 1, "templates": 1, "certificates": 1, "health_coverage": {}},
    )
    assert posture["score"] <= 69
    assert any("critical ADCS findings" in item for item in posture["score_explanation"])
