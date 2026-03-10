from app.models.entities import CertificateTemplate, TemplatePermission
from app.services.risk_engine import evaluate_templates


def test_critical_rule_triggers():
    t = CertificateTemplate(name='T1', display_name='T1', eku=['Client Authentication'], enrollee_supplies_subject=True, manager_approval=False, authorized_signatures=0, validity_days=1000, renewal_days=30, published_to=['CA1'])
    t.permissions = [TemplatePermission(principal='Authenticated Users', can_enroll=True, can_autoenroll=False)]
    findings = evaluate_templates([t])
    ids = {f.rule_id for f in findings}
    assert 'ESC-LIKE-001' in ids
    assert 'TPL-VALIDITY-001' in ids
