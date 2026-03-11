from app.models.entities import CertificateAuthority, CertificateTemplate, TemplatePermission
from app.services.risk_engine import evaluate_templates


def test_esc1_and_validity_rules_trigger_with_legacy_broad_permission():
    t = CertificateTemplate(
        name='UserAuthTpl',
        display_name='UserAuthTpl',
        eku=['Client Authentication'],
        enrollee_supplies_subject=True,
        manager_approval=False,
        authorized_signatures=0,
        validity_days=1000,
        renewal_days=30,
        published_to=['CA1'],
    )
    t.permissions = [TemplatePermission(principal='Authenticated Users', can_enroll=True, can_autoenroll=False)]
    findings, coverage = evaluate_templates([t], [CertificateAuthority(name='CA1', dns_name='ca.local', status='online', config_json={})])
    ids = {f.rule_id for f in findings}
    assert 'ESC1-LIKE-001' in ids
    assert 'TPL-VALIDITY-001' in ids
    assert coverage['ESC1-like'] == 'detected'


def test_any_purpose_detection():
    t = CertificateTemplate(name='AnyPurposeTpl', display_name='AnyPurposeTpl', eku=['2.5.29.37.0'], validity_days=365, renewal_days=30)
    t.permissions = [TemplatePermission(principal='Domain Users', can_enroll=True, can_autoenroll=False)]
    findings, _ = evaluate_templates([t], [])
    assert any(f.rule_id == 'ESC2-LIKE-001' for f in findings)
