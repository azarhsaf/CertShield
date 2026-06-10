from app.models.entities import CertificateAuthority, CertificateTemplate
from app.services.risk_engine import evaluate_templates


def test_advanced_ca_and_acl_findings_are_detected_from_additive_metadata():
    template = CertificateTemplate(
        name="WritableTemplate",
        display_name="Writable Template",
        eku=[],
        validity_days=365,
        renewal_days=30,
        raw_json={
            "acl_assessed": True,
            "acl_details": [{"principal": "Domain Users", "rights": ["GenericWrite"]}],
        },
    )
    template.permissions = []
    ca = CertificateAuthority(
        name="Corp-CA",
        dns_name="ca.corp.local",
        status="online",
        config_json={
            "editf_attributesubjectaltname2": True,
            "manage_ca_principals": ["Authenticated Users"],
            "web_enrollment_enabled": True,
            "ntlm_enabled": True,
            "epa_enabled": False,
            "delegated_admin_principals": ["Domain Users"],
            "pki_control_paths": [{"object": "CN=Public Key Services", "right": "WriteDACL"}],
        },
    )

    findings, coverage = evaluate_templates([template], [ca])
    rule_ids = {finding.rule_id for finding in findings}

    assert "ESC4-LIKE-001" in rule_ids
    assert "ESC5-LIKE-001" in rule_ids
    assert "ESC6-LIKE-001" in rule_ids
    assert "ESC7-LIKE-001" in rule_ids
    assert "ESC8-LIKE-001" in rule_ids
    assert "TIER0-PKI-001" in rule_ids
    assert coverage["ESC4-like"] == "detected"
    assert coverage["ESC6-like"] == "detected"
