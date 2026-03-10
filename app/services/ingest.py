from collections import Counter
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.entities import (
    AuditLog,
    CertificateAuthority,
    CertificateTemplate,
    Finding,
    IssuedCertificate,
    Scan,
    TemplatePermission,
)
from app.schemas.collector import CollectorPayload
from app.services.risk_engine import evaluate_templates


class IngestService:
    @staticmethod
    def ingest(db: Session, payload: CollectorPayload, actor: str = "collector") -> Scan:
        scan = Scan(domain_name=payload.domain_name, source=payload.source_host, started_at=datetime.utcnow())
        db.add(scan)
        db.flush()

        for ca in payload.cas:
            db.add(CertificateAuthority(scan_id=scan.id, name=ca.name, dns_name=ca.dns_name, status=ca.status, config_json=ca.config))

        templates = []
        for template in payload.templates:
            tpl = CertificateTemplate(
                scan_id=scan.id,
                name=template.name,
                display_name=template.display_name,
                eku=template.eku,
                enrollee_supplies_subject=template.enrollee_supplies_subject,
                manager_approval=template.manager_approval,
                authorized_signatures=template.authorized_signatures,
                validity_days=template.validity_days,
                renewal_days=template.renewal_days,
                published_to=template.published_to,
                raw_json=template.raw,
            )
            db.add(tpl)
            db.flush()
            for perm in template.permissions:
                db.add(TemplatePermission(template_id=tpl.id, principal=perm.principal, can_enroll=perm.can_enroll, can_autoenroll=perm.can_autoenroll))
            templates.append(tpl)

        for cert in payload.issued_certificates:
            db.add(IssuedCertificate(scan_id=scan.id, request_id=cert.request_id, requester=cert.requester, template_name=cert.template_name, subject=cert.subject, san=cert.san, issued_at=cert.issued_at, expires_at=cert.expires_at, status=cert.status))

        db.flush()
        findings = evaluate_templates(templates)
        severity_counter = Counter()
        for f in findings:
            severity_counter[f.severity] += 1
            db.add(Finding(scan_id=scan.id, rule_id=f.rule_id, severity=f.severity, title=f.title, affected_object=f.affected_object, rationale=f.rationale, evidence_json=f.evidence, remediation=f.remediation, reference=f.reference))

        scan.completed_at = datetime.utcnow()
        scan.summary_json = {
            "cas": len(payload.cas),
            "templates": len(payload.templates),
            "certificates": len(payload.issued_certificates),
            "findings": len(findings),
            "severity": dict(severity_counter),
        }

        db.add(AuditLog(actor=actor, action="scan_ingested", details_json={"scan_id": scan.id, "domain": payload.domain_name}))
        db.commit()
        db.refresh(scan)
        return scan
