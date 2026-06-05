from dataclasses import dataclass
from typing import Any

from app.models.entities import CertificateAuthority, CertificateTemplate


@dataclass
class BestPracticeAssessmentItem:
    category: str
    title: str
    status: str
    severity: str
    affected_object: str
    evidence: dict
    recommendation: str
    business_impact: str
    technical_impact: str
    confidence: str
    control_refs: list[str]


BROAD_PRINCIPALS = {"authenticated users", "domain users", "everyone"}


def _cfg(ca: CertificateAuthority) -> dict:
    return ca.config_json or {}


def _raw(template: CertificateTemplate) -> dict:
    return template.raw_json or {}


def _join_eku(template: CertificateTemplate) -> str:
    return " ".join(template.eku or []).lower()


def _has_client_auth(template: CertificateTemplate) -> bool:
    eku = _join_eku(template)
    return "client authentication" in eku or "1.3.6.1.5.5.7.3.2" in eku


def _has_broad_enroll(template: CertificateTemplate) -> bool:
    return any((p.can_enroll or p.can_autoenroll) and p.principal.lower() in BROAD_PRINCIPALS for p in template.permissions)


def _item(
    category: str,
    title: str,
    status: str,
    severity: str,
    affected_object: str,
    evidence: dict,
    recommendation: str,
    business_impact: str,
    technical_impact: str,
    confidence: str = "medium",
    control_refs: list[str] | None = None,
) -> BestPracticeAssessmentItem:
    return BestPracticeAssessmentItem(
        category=category,
        title=title,
        status=status,
        severity=severity,
        affected_object=affected_object,
        evidence=evidence,
        recommendation=recommendation,
        business_impact=business_impact,
        technical_impact=technical_impact,
        confidence=confidence,
        control_refs=control_refs or ["PKI governance control placeholder"],
    )


def _bool_check(category: str, title: str, ca_name: str, value: Any, expected: bool, fail_severity: str, recommendation: str, business_impact: str, technical_impact: str) -> BestPracticeAssessmentItem:
    if value is None:
        return _item(category, title, "Not Assessed", "Info", ca_name, {}, recommendation, business_impact, technical_impact, "low")
    passed = bool(value) is expected
    return _item(category, title, "Pass" if passed else "Fail", "Info" if passed else fail_severity, ca_name, {"observed": value, "expected": expected}, recommendation, business_impact, technical_impact, "medium")


def _root_ca_checks(ca: CertificateAuthority) -> list[BestPracticeAssessmentItem]:
    config = _cfg(ca)
    name = ca.name
    return [
        _bool_check("Root CA design", "Root CA should be offline", name, config.get("is_offline"), True, "Critical", "Keep the root CA offline except for controlled signing and CRL publication events.", "Reduces the likelihood that a root key compromise invalidates trust across the organization.", "Limits interactive and network exposure for the root CA private key."),
        _bool_check("Root CA design", "Root CA should not be domain joined", name, config.get("domain_joined"), False, "High", "Keep root CAs out of Active Directory domain membership.", "Reduces business-wide trust disruption if AD administrative paths are compromised.", "Separates root CA administration from domain identity and policy paths."),
        _bool_check("Root CA design", "Root CA should not issue end-entity certificates", name, config.get("issues_end_entity"), False, "High", "Use issuing CAs for end-entity certificates and reserve the root for CA signing operations.", "Preserves clean trust hierarchy and auditability.", "Prevents root CA direct dependency for routine certificate issuance."),
        _bool_check("CA key protection", "Root CA private key should be offline or HSM protected", name, config.get("private_key_protected"), True, "High", "Protect the root CA private key with offline storage or an HSM-backed key ceremony.", "Protects the highest-value PKI trust anchor.", "Reduces key extraction and unauthorized signing risk."),
        _bool_check("Documentation and operational governance", "Root CA key ceremony should be documented", name, config.get("key_ceremony_documented"), True, "Medium", "Document root CA key ceremony, authorized participants, approvals, and evidence retention.", "Improves audit readiness and operational continuity.", "Provides repeatable controls for root CA operations."),
        _bool_check("Root CA design", "Root CA access should be restricted", name, config.get("restricted_access"), True, "High", "Restrict root CA access to dedicated PKI administrators with monitored approval paths.", "Limits blast radius from general administrative compromise.", "Reduces the number of principals able to influence root trust."),
    ]


def _issuing_ca_checks(ca: CertificateAuthority) -> list[BestPracticeAssessmentItem]:
    config = _cfg(ca)
    name = ca.name
    signature_algorithm = str(config.get("signature_algorithm") or config.get("signature_hash") or "").lower()
    key_size = config.get("key_size")
    items = [
        _bool_check("Issuing CA design", "Issuing CA should not be installed on a domain controller", name, config.get("installed_on_domain_controller"), False, "Critical", "Move issuing CA roles away from domain controllers and onto dedicated PKI infrastructure.", "Reduces coupling between AD outage/compromise and PKI issuance capability.", "Separates CA service attack surface from domain controller duties."),
        _bool_check("CA key protection", "Issuing CA private key should be HSM protected where possible", name, config.get("private_key_protected"), True, "Medium", "Use HSM or strong software key protection for issuing CA private keys according to risk tier.", "Protects certificate issuance continuity and trust integrity.", "Reduces key extraction and unauthorized CA signing risk."),
        _bool_check("Auditing and monitoring", "CA auditing should be enabled", name, config.get("audit_enabled"), True, "High", "Enable CA auditing and forward relevant events to monitoring systems.", "Improves incident investigation and audit evidence quality.", "Captures issuance, configuration, and administrative activity."),
        _bool_check("Backup and recovery", "CA backup should be configured", name, config.get("backup_configured"), True, "Medium", "Document and test CA system, certificate, key, and database backup procedures.", "Reduces downtime and trust recovery risk during CA failure.", "Ensures CA database and key material can be restored under approved controls."),
    ]
    if signature_algorithm:
        weak = "sha1" in signature_algorithm or "md5" in signature_algorithm
        items.append(_item("CA configuration", "CA should use SHA256 or better", "Fail" if weak else "Pass", "High" if weak else "Info", name, {"signature_algorithm": signature_algorithm}, "Move CA certificate and issuance configuration to SHA256 or stronger where compatibility allows.", "Reduces audit and relying-party trust failures tied to weak algorithms.", "Avoids legacy signature algorithms with known weaknesses.", "medium"))
    else:
        items.append(_item("CA configuration", "CA signature algorithm not assessed", "Not Assessed", "Info", name, {}, "Collect CA certificate signature algorithm during certificate metadata collection.", "Missing cryptographic posture data can delay audit readiness.", "Cannot confirm hash algorithm strength without certificate metadata.", "low"))
    if key_size:
        weak_key = int(key_size) < 2048
        items.append(_item("CA configuration", "CA key size should be RSA 2048 or stronger", "Fail" if weak_key else "Pass", "High" if weak_key else "Info", name, {"key_size": key_size}, "Use RSA 2048 or stronger, or an approved ECC equivalent, for CA keys.", "Reduces long-term trust and compliance risk.", "Improves cryptographic baseline strength.", "medium"))
    else:
        items.append(_item("CA configuration", "CA key size not assessed", "Not Assessed", "Info", name, {}, "Collect CA certificate key size during certificate metadata collection.", "Missing cryptographic posture data can delay audit readiness.", "Cannot confirm CA key strength without certificate metadata.", "low"))
    cdp = config.get("cdp_urls") or config.get("crl_urls")
    aia = config.get("aia_urls")
    has_publication = bool(cdp) and bool(aia)
    items.append(_item("CRL/AIA/OCSP publication", "CA should publish CRL and AIA locations", "Pass" if has_publication else "Warning", "Info" if has_publication else "Medium", name, {"cdp_urls": cdp, "aia_urls": aia}, "Publish and monitor CRL/CDP and AIA locations reachable by relying systems.", "Prevents outages and validation failures caused by missing chain or revocation data.", "Supports certificate path building and revocation checking.", "medium" if cdp is not None or aia is not None else "low"))
    return items


def _template_checks(template: CertificateTemplate) -> list[BestPracticeAssessmentItem]:
    raw = _raw(template)
    name = template.name
    broad = _has_broad_enroll(template)
    client_auth = _has_client_auth(template)
    sensitive = client_auth or bool(raw.get("sensitive"))
    items = [
        _item("Certificate template governance", "Avoid Authenticated Users enrollment on high-risk templates", "Fail" if broad and sensitive else "Pass", "High" if broad and sensitive else "Info", name, {"broad_enrollment": broad, "sensitive": sensitive}, "Remove broad principals from high-risk template enrollment and scope access to dedicated security groups.", "Reduces the chance that routine users can access high-impact certificate workflows.", "Constrains enrollment permissions to approved identities.", "high"),
        _item("Certificate template governance", "Avoid requester-supplied SAN unless approved", "Fail" if template.enrollee_supplies_subject and sensitive else "Pass", "High" if template.enrollee_supplies_subject and sensitive else "Info", name, {"enrollee_supplies_subject": template.enrollee_supplies_subject, "sensitive": sensitive}, "Disable requester-supplied subject/SAN on sensitive templates unless formally approved and monitored.", "Reduces identity assurance and audit risk for certificate-backed authentication.", "Prevents requesters from controlling identity fields on sensitive templates.", "high"),
        _item("Certificate template governance", "Require manager approval for sensitive templates", "Warning" if sensitive and not template.manager_approval else "Pass", "Medium" if sensitive and not template.manager_approval else "Info", name, {"manager_approval": template.manager_approval, "sensitive": sensitive}, "Use manager approval only for certificate workflows where manual approval is an intended compensating control.", "Adds oversight to high-impact issuance without applying generic approval everywhere.", "Adds an issuance gate for selected sensitive templates.", "medium"),
        _item("Certificate template governance", "Require authorized signatures for high-impact templates", "Warning" if sensitive and template.authorized_signatures == 0 else "Pass", "Medium" if sensitive and template.authorized_signatures == 0 else "Info", name, {"authorized_signatures": template.authorized_signatures, "sensitive": sensitive}, "Require authorized signatures for high-impact templates where enrollment should depend on a trusted approval chain.", "Improves governance over certificates that can affect privileged access or identity assurance.", "Adds cryptographic/request-signature gating for selected templates.", "medium"),
    ]
    exportable = raw.get("private_key_exportable")
    if exportable is not None:
        items.append(_item("Certificate template governance", "Avoid exportable private keys", "Fail" if exportable else "Pass", "Medium" if exportable else "Info", name, {"private_key_exportable": exportable}, "Disable exportable private keys unless a documented business case requires it.", "Reduces risk from key copying and uncontrolled certificate reuse.", "Keeps private keys bound to approved storage locations.", "medium"))
    key_size = raw.get("minimum_key_size") or raw.get("min_key_size")
    if key_size is not None:
        weak_key = int(key_size) < 2048
        items.append(_item("Certificate template governance", "Avoid weak template key sizes", "Fail" if weak_key else "Pass", "High" if weak_key else "Info", name, {"minimum_key_size": key_size}, "Set template minimum key size to RSA 2048 or stronger, or an approved ECC equivalent.", "Reduces cryptographic and audit risk for issued certificates.", "Improves key strength for newly issued certificates.", "medium"))
    hash_algorithm = str(raw.get("hash_algorithm") or raw.get("signature_algorithm") or "").lower()
    if hash_algorithm:
        weak_hash = "sha1" in hash_algorithm or "md5" in hash_algorithm
        items.append(_item("Certificate template governance", "Avoid SHA1 or weaker hash algorithms", "Fail" if weak_hash else "Pass", "High" if weak_hash else "Info", name, {"hash_algorithm": hash_algorithm}, "Use SHA256 or stronger for certificate templates and related issuance policy.", "Supports compliance and relying-party trust expectations.", "Avoids legacy weak hash algorithms.", "medium"))
    if template.validity_days > 825:
        items.append(_item("Certificate lifecycle management", "Avoid overly long certificate validity", "Warning", "Medium", name, {"validity_days": template.validity_days}, "Reduce validity for end-entity templates to the organizational baseline and automate renewal where appropriate.", "Limits long-lived exposure from stale or mis-issued certificates.", "Shortens the window where an issued certificate remains trusted.", "high"))
    enabled = raw.get("enabled")
    if enabled is False:
        items.append(_item("Certificate template governance", "Disable unused templates", "Pass", "Info", name, {"enabled": enabled}, "Keep unused templates disabled and document ownership.", "Reduces template sprawl and review workload.", "Removes inactive issuance paths from routine use.", "medium"))
    elif raw.get("unused") is True:
        items.append(_item("Certificate template governance", "Disable unused templates", "Warning", "Low", name, {"unused": True}, "Disable templates that no longer have an assigned business owner or active use case.", "Reduces governance gaps and unnecessary issuance surface.", "Removes stale templates from publication and enrollment workflows.", "medium"))
    return items


def assess_best_practices(cas: list[CertificateAuthority], templates: list[CertificateTemplate], assessment_hints: dict | None = None) -> tuple[list[BestPracticeAssessmentItem], dict]:
    hints = assessment_hints or {}
    items: list[BestPracticeAssessmentItem] = []

    root_seen = False
    issuing_seen = False
    for ca in cas:
        config = _cfg(ca)
        role = str(config.get("role") or "").lower()
        is_root = bool(config.get("is_root")) or role == "root"
        if is_root:
            root_seen = True
            items.extend(_root_ca_checks(ca))
        else:
            issuing_seen = True
            items.extend(_issuing_ca_checks(ca))

    if not root_seen:
        items.append(_item("Root CA design", "Root CA design not assessed", "Not Assessed", "Info", "Root CA", {"root_ca_seen": False}, "Collect or document root CA metadata such as offline state, domain membership, CRL publication, and key ceremony evidence.", "Root CA design gaps can remain invisible without explicit inventory.", "The scanner cannot confirm root CA tiering or key protection from current data.", "low"))
    if not issuing_seen:
        items.append(_item("Issuing CA design", "Issuing CA design not assessed", "Not Assessed", "Info", "Issuing CA", {"issuing_ca_seen": False}, "Collect issuing CA configuration metadata and role placement.", "Issuing CA posture gaps can remain invisible without explicit inventory.", "The scanner cannot confirm service placement, auditing, backup, or cryptographic baseline from current data.", "low"))

    for template in templates:
        items.extend(_template_checks(template))

    if not templates:
        items.append(_item("Certificate template governance", "Certificate templates not collected", "Not Assessed", "Info", "Certificate templates", {}, "Collect certificate templates so governance checks can run.", "Template governance risk cannot be prioritized without template inventory.", "No template flags, EKUs, or permissions were available to assess.", "low"))

    if hints.get("ca_backup") == "not_assessed":
        items.append(_item("Backup and recovery", "CA backup evidence not assessed", "Not Assessed", "Info", "PKI operations", {"hint": hints.get("ca_backup")}, "Add documented CA backup evidence or collector metadata in a future scan.", "Backup gaps can lead to prolonged PKI outage during CA failure.", "Recovery posture cannot be confirmed from current collector data.", "low"))

    counts: dict[str, int] = {}
    for item in items:
        counts[item.status] = counts.get(item.status, 0) + 1
    penalty = counts.get("Fail", 0) * 12 + counts.get("Warning", 0) * 6 + counts.get("Not Assessed", 0) * 2
    score = max(0, 100 - penalty)
    summary = {
        "score": score,
        "counts": counts,
        "total": len(items),
        "top_gap_count": counts.get("Fail", 0) + counts.get("Warning", 0),
    }
    return items, summary
