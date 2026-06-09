from __future__ import annotations

from collections import Counter

from app.models.entities import CertificateAuthority, CertificateTemplate, IssuedCertificate
from app.services.pki_hierarchy import ca_certificate, ca_role, key_protection
from app.services.risk_engine import _has_any_purpose, _has_client_auth


def _display_status(status: str) -> str:
    return {"Fail": "High Risk", "Warning": "Needs Attention"}.get(status, status)


def _bp(
    category: str,
    title: str,
    status: str,
    severity: str,
    affected: str,
    evidence: dict,
    business: str,
    technical: str,
    recommendation: str,
    confidence: str = "medium",
    data_source: str = "collector",
    not_assessed_reason: str | None = None,
) -> dict:
    return {
        "category": category,
        "title": title,
        "status": status,
        "display_status": _display_status(status),
        "severity": severity,
        "affected_object": affected,
        "evidence": evidence,
        "business_impact": business,
        "technical_impact": technical,
        "recommendation": recommendation,
        "confidence": confidence,
        "data_source": data_source,
        "not_assessed_reason": not_assessed_reason,
    }


def _score(items: list[dict]) -> tuple[int | None, str, dict, list[str]]:
    if not items:
        return None, "Unknown", {}, ["No best-practice checks were produced from the latest scan."]

    counts = Counter(item["status"] for item in items)
    score = 100
    risk_values = {
        ("Fail", "Critical"): 20,
        ("Fail", "High"): 15,
        ("Fail", "Medium"): 8,
        ("Warning", "Critical"): 10,
        ("Warning", "High"): 8,
        ("Warning", "Medium"): 4,
    }
    for item in items:
        score -= risk_values.get((item["status"], item["severity"]), 0)
    if items and counts.get("Not Assessed", 0) / len(items) > 0.5:
        score = min(score, 74)
    score = max(0, min(100, score))
    if score >= 90:
        status = "Excellent"
    elif score >= 75:
        status = "Good"
    elif score >= 60:
        status = "Needs Attention"
    elif score >= 40:
        status = "High Risk"
    else:
        status = "Critical"
    explanations = [
        "Best-practice assurance uses confirmed gaps and lowers coverage for Not Assessed controls.",
        f"{counts.get('Not Assessed', 0)} controls are Not Assessed due to missing evidence.",
    ]
    return score, status, dict(counts), explanations


def _config_bool(config: dict, key: str) -> bool | None:
    value = config.get(key)
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).lower()
    if text in {"true", "yes", "1", "enabled"}:
        return True
    if text in {"false", "no", "0", "disabled"}:
        return False
    return None


def _ca_practices(ca: CertificateAuthority) -> list[dict]:
    config = ca.config_json or {}
    cert = ca_certificate(config)
    role = ca_role(ca)
    is_root = role == "root"
    category = "Root CA" if is_root else "Issuing CA" if role == "issuing" else "PKI Architecture"
    items: list[dict] = []
    role_status = "Pass" if role in {"root", "issuing"} else "Not Assessed"
    items.append(
        _bp(
            "PKI Architecture",
            "CA role classified from certificate subject/issuer",
            role_status,
            "Low" if role_status == "Pass" else "Medium",
            ca.name,
            {
                "role": role,
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "evidence_source": "CA certificate subject/issuer",
            },
            "Clear CA role classification supports PKI ownership and prioritization.",
            "Root and issuing CA controls depend on certificate chain evidence.",
            "Collect CA certificate Subject/Issuer metadata for every CA.",
            "high" if role_status == "Pass" else "low",
            data_source="CA certificate subject/issuer",
            not_assessed_reason="Collector did not provide CA certificate Subject/Issuer evidence." if role_status == "Not Assessed" else None,
        )
    )
    if role in {"root", "issuing"}:
        items.append(
            _bp(
                category,
                "Root CA detected" if role == "root" else "Issuing CA detected",
                "Pass",
                "Low",
                ca.name,
                {
                    "parent_ca": cert.get("issuer") if role == "issuing" else "Self-signed root",
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "evidence_source": "CA certificate subject/issuer",
                },
                "PKI role is known from certificate evidence.",
                "Role-specific controls can be assessed against the correct CA tier.",
                "Maintain chain documentation and continue collecting CA certificate metadata.",
                "high",
                data_source="CA certificate subject/issuer",
            )
        )

    if is_root:
        offline = _config_bool(config, "offline")
        items.append(
            _bp(
                category,
                "Root CA should be offline",
                "Pass" if offline is True else "Fail" if offline is False else "Not Assessed",
                "Critical",
                ca.name,
                {"offline": offline},
                "Online root CAs increase enterprise trust blast radius.",
                "Root private key exposure can compromise the PKI hierarchy.",
                "Keep the root CA offline except controlled CRL/key ceremony operations.",
                "high" if offline is not None else "low",
                not_assessed_reason="Collector did not provide root online/offline evidence." if offline is None else None,
            )
        )
        domain_joined = _config_bool(config, "domain_joined")
        items.append(
            _bp(
                category,
                "Root CA should not be domain joined",
                "Pass" if domain_joined is False else "Fail" if domain_joined is True else "Not Assessed",
                "High",
                ca.name,
                {"domain_joined": domain_joined},
                "Domain compromise should not directly expose root CA trust.",
                "Domain-joined root CA increases attack surface and administrative dependencies.",
                "Keep root CA systems outside the domain and tightly controlled.",
                not_assessed_reason="Collector did not provide domain-join evidence." if domain_joined is None else None,
            )
        )
    else:
        on_dc = _config_bool(config, "installed_on_domain_controller")
        items.append(
            _bp(
                category,
                "Issuing CA should not run on a domain controller",
                "Pass" if on_dc is False else "Fail" if on_dc is True else "Not Assessed",
                "Critical" if on_dc is True else "High",
                ca.name,
                {"installed_on_domain_controller": on_dc},
                "Combining CA and DC roles increases business impact of host compromise.",
                "CA private key and domain controller attack surface become coupled.",
                "Run issuing CAs on dedicated hardened servers, not domain controllers.",
                not_assessed_reason="Collector did not provide server role evidence." if on_dc is None else None,
            )
        )

    audit = _config_bool(config, "auditing_enabled")
    items.append(
        _bp(
            category,
            "CA auditing should be enabled",
            "Pass" if audit is True else "Fail" if audit is False else "Not Assessed",
            "High",
            ca.name,
            {"auditing_enabled": audit},
            "Missing audit trails delay incident response and compliance review.",
            "Issuance and configuration changes may not be traceable.",
            "Enable CA auditing for issuance, revocation, and configuration changes.",
            not_assessed_reason="Not Assessed - collector did not collect CA AuditFilter yet." if audit is None else None,
        )
    )

    backup = _config_bool(config, "backup_documented")
    items.append(
        _bp(
            "Backup and Recovery",
            "CA backup and recovery should be documented",
            "Pass" if backup is True else "Warning" if backup is False else "Not Assessed",
            "Medium",
            ca.name,
            {"backup_documented": backup},
            "Unvalidated recovery increases outage duration during CA incidents.",
            "CA database/private key recovery may be inconsistent or impossible.",
            "Document and periodically test CA certificate, key, and database recovery.",
            not_assessed_reason="Collector did not provide backup evidence." if backup is None else None,
        )
    )
    return items


def _key_protection_practice(ca: CertificateAuthority) -> dict:
    config = ca.config_json or {}
    role_key = ca_role(ca)
    if role_key == "unknown":
        role_key = str(config.get("ca_type", "issuing")).lower()
    role = "Root CA" if role_key == "root" else "Issuing CA" if role_key == "issuing" else "Unclassified CA"
    kp = key_protection(config)
    if kp["status"] == "HSM Protected":
        status = "Pass"
        severity = "Low"
        recommendation = "Continue validating HSM/external key custody and administrative controls."
        reason = None
    elif kp["status"] == "Software Key":
        status = "Fail" if role == "Root CA" else "Warning"
        severity = "Critical" if role == "Root CA" else "High"
        recommendation = "Move high-value CA keys to HSM/external KMS where feasible and document compensating controls."
        reason = None
    elif kp["status"] == "Unknown Provider":
        status = "Warning"
        severity = "Medium"
        recommendation = "Review the collected CA crypto provider and classify whether it is HSM, external KMS, or software-backed."
        reason = None
    else:
        status = "Not Assessed"
        severity = "Medium"
        recommendation = "Collect CA crypto provider / key storage evidence and classify key protection."
        reason = "Collector did not provide CA key protection evidence."
    return _bp(
        "Key Protection",
        f"{role} key protection should be known and appropriate",
        status,
        severity,
        ca.name,
        kp,
        "CA private key custody is a core PKI trust dependency.",
        "Software or unknown CA key storage can increase compromise and recovery risk.",
        recommendation,
        "medium" if kp["status"] != "Unknown" else "low",
        not_assessed_reason=reason,
    )


def _template_practices(template: CertificateTemplate) -> list[dict]:
    raw = template.raw_json or {}
    permission_data_available = bool(template.permissions) or raw.get("permissions_assessed") is True
    principals = {
        p.principal.lower().split("\\")[-1]: p
        for p in template.permissions
        if p.can_enroll or p.can_autoenroll
    }
    broad_principals = "authenticated users" in principals or "domain users" in principals
    auth_capable = _has_client_auth(template.eku)
    owner = raw.get("business_owner")
    if not permission_data_available:
        broad_status = "Not Assessed"
        broad_severity = "High"
        broad_reason = "Collector did not provide template permission metadata."
    elif auth_capable and broad_principals and template.enrollee_supplies_subject:
        broad_status = "Fail"
        broad_severity = "Critical"
        broad_reason = None
    elif broad_principals:
        broad_status = "Warning"
        broad_severity = "High" if auth_capable else "Medium"
        broad_reason = None
    else:
        broad_status = "Pass"
        broad_severity = "Low"
        broad_reason = None

    return [
        _bp(
            "Templates",
            "Avoid broad enrollment on authentication templates",
            broad_status,
            broad_severity,
            template.name,
            {
                "eku": template.eku,
                "principals": list(principals),
                "permission_data_available": permission_data_available,
                "enrollee_supplies_subject": template.enrollee_supplies_subject,
            },
            "Broad enrollment on authentication templates can create enterprise identity risk.",
            "Low-privileged principals may obtain authentication-capable certificates if other safeguards are weak.",
            "Remove Authenticated Users / Domain Users from Enroll or AutoEnroll and scope to dedicated security groups.",
            "high" if permission_data_available else "low",
            not_assessed_reason=broad_reason,
        ),
        _bp(
            "Templates",
            "Avoid requester-supplied subject/SAN unless approved",
            "Warning" if template.enrollee_supplies_subject else "Pass",
            "High" if template.enrollee_supplies_subject else "Low",
            template.name,
            {"enrollee_supplies_subject": template.enrollee_supplies_subject},
            "Requester-controlled identity fields can create governance and identity assurance gaps.",
            "Subject/SAN values may not be authoritative unless tightly governed.",
            "Disable enrollee-supplied subject/SAN unless a documented business case requires it.",
            "high",
        ),
        _bp(
            "Templates",
            "Avoid Any Purpose EKU on templates",
            "Fail" if _has_any_purpose(template.eku) else "Pass",
            "High",
            template.name,
            {"eku": template.eku},
            "Overly broad certificate usage weakens policy boundaries.",
            "Certificates may be accepted for unintended purposes.",
            "Replace Any Purpose usage with purpose-specific templates.",
            "high",
        ),
        _bp(
            "Templates",
            "Avoid overly long validity periods",
            "Warning" if template.validity_days > 825 else "Pass",
            "Medium",
            template.name,
            {"validity_days": template.validity_days},
            "Long-lived certificates increase exposure windows.",
            "Mis-issued certificates remain valid longer and are harder to remediate.",
            "Reduce validity to the organization baseline for the certificate purpose.",
            "high",
        ),
        _bp(
            "Templates",
            "Important templates should have a business owner",
            "Pass" if owner else "Not Assessed",
            "Medium",
            template.name,
            {"business_owner": owner or "Not collected"},
            "Unowned templates complicate risk acceptance and remediation.",
            "Template changes may lack accountable review.",
            "Assign and document template owners for important templates.",
            "medium" if owner else "low",
            not_assessed_reason="Collector did not provide business owner metadata." if not owner else None,
        ),
    ]


def assess_best_practices(
    cas: list[CertificateAuthority],
    templates: list[CertificateTemplate],
    certificates: list[IssuedCertificate],
    findings: list[object],
) -> dict:
    items: list[dict] = []
    for ca in cas:
        items.extend(_ca_practices(ca))
        items.append(_key_protection_practice(ca))
    for template in templates:
        items.extend(_template_practices(template))

    privileged_seen = any("admin" in (cert.requester or "").lower() for cert in certificates)
    items.extend(
        [
            _bp(
                "Lifecycle",
                "Certificate expiry should be monitored",
                "Pass" if certificates else "Warning",
                "Medium",
                "Certificate inventory",
                {"issued_certificates": len(certificates)},
                "Certificate outages can disrupt business services.",
                "Expired certificates break authentication, TLS, and signing workflows.",
                "Run the collector on a schedule and alert on 30/60/90-day certificate expiry windows.",
                "high",
            ),
            _bp(
                "Lifecycle",
                "Certificates issued to privileged accounts should be reviewed",
                "Warning" if privileged_seen else "Not Assessed",
                "High",
                "Issued certificates",
                {"privileged_account_hint_seen": privileged_seen},
                "Privileged account certificates require stronger ownership and monitoring.",
                "Privileged certs may expand access if mishandled.",
                "Collect account context and review certificates issued to privileged identities.",
                "medium" if privileged_seen else "low",
                not_assessed_reason="Collector did not provide authoritative privilege/account status metadata." if not privileged_seen else None,
            ),
            _bp(
                "Auditing",
                "Collector should run on a schedule",
                "Not Assessed",
                "Medium",
                "Collector",
                {},
                "Stale data weakens posture management and audit readiness.",
                "Findings and expiry windows may be missed between manual scans.",
                "Run the Windows collector on a scheduled task and monitor ingest freshness.",
                "low",
                data_source="deployment",
                not_assessed_reason="Scheduling evidence is not collected by the current payload.",
            ),
            _bp(
                "Backup and Recovery",
                "Offline root backup should be protected",
                "Not Assessed",
                "High",
                "Root CA",
                {},
                "Root recovery material must be protected against theft and loss.",
                "Unprotected backups can compromise or prevent PKI recovery.",
                "Protect offline root backups with documented custody and recovery tests.",
                "low",
                data_source="operator evidence",
                not_assessed_reason="Backup custody cannot be confirmed by the collector.",
            ),
        ]
    )

    score, status, counts, explanations = _score(items)
    grouped: dict[str, list[dict]] = {}
    for item in items:
        grouped.setdefault(item["category"], []).append(item)
    summary_cards = []
    for category, category_items in grouped.items():
        category_counts = Counter(item["status"] for item in category_items)
        worst = "Fail" if category_counts.get("Fail") else "Warning" if category_counts.get("Warning") else "Not Assessed" if category_counts.get("Not Assessed") else "Pass"
        summary_cards.append(
            {
                "category": category,
                "status": worst,
                "total": len(category_items),
                "fail": category_counts.get("Fail", 0),
                "warning": category_counts.get("Warning", 0),
                "not_assessed": category_counts.get("Not Assessed", 0),
                "recommendation": next((item["recommendation"] for item in category_items if item["status"] in {"Fail", "Warning", "Not Assessed"}), "No immediate gap detected."),
            }
        )
    top_gaps = [item for item in items if item["status"] in {"Fail", "Warning"}]
    top_gaps.sort(key=lambda item: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(item["severity"], 4))
    coverage = round((len(items) - counts.get("Not Assessed", 0)) * 100 / len(items)) if items else 0
    confidence = "High" if coverage >= 80 else "Medium" if coverage >= 50 else "Low"
    return {
        "score": score,
        "status": status,
        "grade": status,
        "confidence": confidence,
        "coverage": coverage,
        "score_explanation": explanations,
        "top_factors": [item["title"] for item in top_gaps[:5]],
        "limited_visibility": bool(items) and counts.get("Not Assessed", 0) / len(items) > 0.5,
        "counts": counts,
        "items": items,
        "grouped": grouped,
        "summary_cards": summary_cards,
        "top_gaps": top_gaps[:8],
    }
