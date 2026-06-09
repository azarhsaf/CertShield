from collections import Counter
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

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
from app.services.assessment_registry import build_assessment_registry
from app.services.best_practices import assess_best_practices
from app.services.health_assessment import assess_pki_health
from app.services.posture_assessment import assess_pki_posture
from app.services.risk_acceptance import active_acceptance_map
from app.services.risk_engine import evaluate_templates


class IngestService:
    @staticmethod
    def ingest(db: Session, payload: CollectorPayload, actor: str = "collector") -> Scan:
        scan = Scan(domain_name=payload.domain_name, source=payload.source_host, started_at=datetime.utcnow())
        db.add(scan)
        db.flush()

        cas = []
        for ca in payload.cas:
            row = CertificateAuthority(
                scan_id=scan.id,
                name=ca.name,
                dns_name=ca.dns_name,
                status=ca.status,
                config_json=ca.config,
            )
            db.add(row)
            cas.append(row)

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
                db.add(
                    TemplatePermission(
                        template_id=tpl.id,
                        principal=perm.principal,
                        can_enroll=perm.can_enroll,
                        can_autoenroll=perm.can_autoenroll,
                    )
                )
            templates.append(tpl)

        certificates = []
        for cert in payload.issued_certificates:
            cert_row = IssuedCertificate(
                    scan_id=scan.id,
                    request_id=cert.request_id,
                    requester=cert.requester,
                    template_name=cert.template_name,
                    subject=cert.subject,
                    san=cert.san,
                    issued_at=cert.issued_at,
                    expires_at=cert.expires_at,
                    status=cert.status,
                )
            db.add(cert_row)
            certificates.append(cert_row)

        db.flush()
        if payload.collector_type == "adcs":
            findings, coverage = evaluate_templates(templates, cas)
        else:
            findings, coverage = [], {"adcs_vulnerability_assessment": "not_assessed"}
        severity_counter = Counter()
        esc_counter = Counter()
        persisted_findings = []
        for f in findings:
            severity_counter[f.severity] += 1
            esc_counter[f.esc_category] += 1
            finding_row = Finding(
                scan_id=scan.id,
                rule_id=f.rule_id,
                esc_category=f.esc_category,
                severity=f.severity,
                confidence=f.confidence,
                coverage_state=f.coverage_state,
                title=f.title,
                affected_object=f.affected_object,
                trigger_conditions=f.trigger_conditions,
                rationale=f.rationale,
                evidence_json=f.evidence,
                remediation=f.remediation,
                remediation_steps_json=f.remediation_steps,
                simulation_summary=f.simulation_summary,
                simulation_json=f.simulation,
                reference=f.reference,
            )
            db.add(finding_row)
            persisted_findings.append(finding_row)

        scan.completed_at = datetime.utcnow()
        scan.coverage_json = coverage
        base_summary = {
            "cas": len(payload.cas),
            "templates": len(payload.templates),
            "certificates": len(payload.issued_certificates),
            "findings": len(findings),
            "severity": dict(severity_counter),
            "by_category": dict(esc_counter),
            "collector_type": payload.collector_type,
            "collector_version": payload.collector_version,
            "schema_version": payload.schema_version,
            "health_coverage": payload.health_coverage,
        }
        db.flush()
        health = assess_pki_health(
            cas,
            templates,
            certificates,
            persisted_findings,
            scan.completed_at,
            payload.collector_version,
            payload.source_host,
            payload.health_coverage,
        )
        best_practices = assess_best_practices(cas, templates, certificates, persisted_findings)
        registry = build_assessment_registry(
            cas, templates, certificates, persisted_findings, health, best_practices, active_acceptance_map(db)
        )
        posture = assess_pki_posture(
            persisted_findings, health, best_practices, coverage, {**base_summary, "registry": registry}, set()
        )
        posture["assurance"] = registry["assurance"]
        posture["score"] = registry["assurance"].get("score")
        posture["status"] = registry["assurance"].get("assurance_level")
        posture["assurance_level"] = registry["assurance"].get("assurance_level")
        posture["coverage"] = registry["assurance"].get("coverage_score")
        posture["why"] = registry["assurance"].get("why", [])
        scan.summary_json = {
            **base_summary,
            "health": health,
            "best_practices": best_practices,
            "posture": posture,
            "registry": registry,
            "remediation_priorities": posture.get("remediation_priorities", {}),
        }
        flag_modified(scan, "summary_json")

        db.add(
            AuditLog(
                actor=actor,
                action="scan_ingested",
                details_json={
                    "scan_id": scan.id,
                    "domain": payload.domain_name,
                    "collector_type": payload.collector_type,
                    "collector_version": payload.collector_version,
                    "schema_version": payload.schema_version,
                },
            )
        )
        db.commit()
        db.refresh(scan)
        return scan
