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
    PkiEnvironment,
    Scan,
    TemplatePermission,
)
from app.schemas.collector import CollectorPayload
from app.services.assessment_registry import build_assessment_registry
from app.services.best_practices import assess_best_practices
from app.services.governance_evidence import governance_evidence_map
from app.services.health_assessment import assess_pki_health
from app.services.posture_assessment import assess_pki_posture
from app.services.risk_acceptance import active_acceptance_map
from app.services.risk_engine import evaluate_templates


def _normalize_key(value: str) -> str:
    return str(value or "").strip().lower().replace(" ", "-")


def _environment_key(payload: CollectorPayload) -> str:
    if payload.environment_key.strip():
        return _normalize_key(payload.environment_key)
    if payload.environment_name.strip():
        return f"{_normalize_key(payload.collector_type)}:{_normalize_key(payload.environment_name)}"
    ca_names = sorted(_normalize_key(ca.name) for ca in payload.cas if ca.name)
    ca_part = ",".join(ca_names) if ca_names else _normalize_key(payload.source_host or "unknown")
    if payload.collector_type == "ejbca":
        label = _normalize_key(payload.pki_label or payload.domain_name or payload.source_host or "ejbca")
        return f"ejbca:{label}:{ca_part}"
    domain = _normalize_key(payload.domain_name or payload.forest_name or payload.source_host or "unknown")
    return f"{_normalize_key(payload.collector_type or 'generic')}:{domain}:{ca_part}"


def _is_demo_payload(payload: CollectorPayload) -> bool:
    markers = " ".join([payload.environment_name, payload.environment_key, payload.domain_name, payload.pki_label, payload.source_host]).lower()
    return any(marker in markers for marker in ("demo", "sample", "fixture")) or payload.domain_name.lower() in {"corp.local", "corp"}


def _resolve_environment(db: Session, payload: CollectorPayload) -> PkiEnvironment:
    key = _environment_key(payload)
    now = datetime.utcnow()

    env = db.query(PkiEnvironment).filter_by(environment_key=key).first()

    collector_type = _normalize_key(payload.collector_type or "generic")
    domain_name = _normalize_key(payload.domain_name)
    forest_name = _normalize_key(payload.forest_name)
    environment_name = _normalize_key(payload.environment_name)

    if not env:
        candidates = db.query(PkiEnvironment).filter_by(is_active=True).order_by(PkiEnvironment.id.asc()).all()

        def same_collector_type(
            candidate: PkiEnvironment,
        ) -> bool:
            return _normalize_key(candidate.collector_type or "generic") == collector_type

        if domain_name:
            env = next(
                (candidate for candidate in candidates if same_collector_type(candidate) and _normalize_key(candidate.domain_name) == domain_name),
                None,
            )

        if not env and forest_name:
            env = next(
                (candidate for candidate in candidates if same_collector_type(candidate) and _normalize_key(candidate.forest_name) == forest_name),
                None,
            )

        if not env and environment_name and not domain_name and not forest_name:
            env = next(
                (candidate for candidate in candidates if same_collector_type(candidate) and _normalize_key(candidate.name) == environment_name),
                None,
            )

    if env:
        env.environment_key = key
        env.collector_type = payload.collector_type or env.collector_type or "generic"

        if payload.environment_name.strip():
            env.name = payload.environment_name.strip()

        if payload.domain_name:
            env.domain_name = payload.domain_name

        if payload.forest_name:
            env.forest_name = payload.forest_name

        if payload.pki_label.strip():
            env.pki_label = payload.pki_label.strip()
        elif not env.pki_label:
            env.pki_label = env.name

        env.is_demo = _is_demo_payload(payload)
        env.is_active = True
        env.updated_at = now

        if env.description and env.description.startswith("Created automatically from a " "monitoring-agent heartbeat."):
            env.description = "Monitoring agent and collector data " "are available."

        db.flush()
        return env

    name = payload.environment_name.strip() or payload.pki_label.strip() or payload.domain_name or key

    if _is_demo_payload(payload) and not name.lower().startswith("demo"):
        name = f"Demo - {name}"

    env = PkiEnvironment(
        name=name,
        environment_key=key,
        collector_type=(payload.collector_type or "generic"),
        domain_name=payload.domain_name or "",
        forest_name=payload.forest_name or "",
        pki_label=payload.pki_label or name,
        is_demo=_is_demo_payload(payload),
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    db.add(env)
    db.flush()
    return env


class IngestService:
    @staticmethod
    def ingest(db: Session, payload: CollectorPayload, actor: str = "collector") -> Scan:
        environment = _resolve_environment(db, payload)
        previous = db.query(Scan).filter_by(environment_id=environment.id, is_current_for_environment=True).order_by(Scan.id.desc()).first()
        sequence = (previous.scan_sequence + 1) if previous else 1
        scan = Scan(
            domain_name=payload.domain_name,
            source=payload.source_host,
            source_host=payload.source_host,
            collector_type=payload.collector_type or "generic",
            collector_version=payload.collector_version,
            schema_version=payload.schema_version,
            collection_mode=payload.collection_mode or "full",
            environment_id=environment.id,
            scan_sequence=sequence,
            previous_scan_id=previous.id if previous else None,
            is_current_for_environment=True,
            started_at=datetime.utcnow(),
        )
        if previous:
            previous.is_current_for_environment = False
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
                validity_days=template.validity_days or 0,
                renewal_days=template.renewal_days or 0,
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
        environment.last_scan_id = scan.id
        environment.last_scan_at = scan.completed_at
        environment.updated_at = scan.completed_at
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
        best_practices = assess_best_practices(
            cas,
            templates,
            certificates,
            persisted_findings,
            governance_evidence_map(db),
        )
        registry = build_assessment_registry(cas, templates, certificates, persisted_findings, health, best_practices, active_acceptance_map(db))
        posture = assess_pki_posture(persisted_findings, health, best_practices, coverage, {**base_summary, "registry": registry}, set())
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
                    "environment_id": environment.id,
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
