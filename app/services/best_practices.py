from __future__ import annotations

from collections import Counter
from typing import Any

from app.models.entities import CertificateAuthority, CertificateTemplate, IssuedCertificate
from app.services.risk_engine import _has_any_purpose, _has_client_auth


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


def _score(items: list[dict]) -> tuple[int | None, str, dict]:
    assessed = [item for item in items if item["status"] != "Not Assessed"]
    counts = dict(Counter(item["status"] for item in items))
    if not assessed:
        return None, "Unknown", counts
    score = 100
    for item in assessed:
        if item["status"] == "Fail":
            score -= 12 if item["severity"] in {"Critical", "High"} else 7
        elif item["status"] == "Warning":
            score -= 5
    score = max(score, 0)
    return score, "Pass" if score >= 90 else "Warning" if score >= 70 else "Fail", counts


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
    ca_type = str(config.get("ca_type", "issuing")).lower()
    is_root = ca_type == "root"
    category = "Root CA" if is_root else "Issuing CA"
    items: list[dict] = []

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
                "High",
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
            not_assessed_reason="Collector did not provide CA audit configuration." if audit is None else None,
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


def _template_practices(template: CertificateTemplate) -> list[dict]:
    principals = {p.principal.lower().split("\\")[-1]: p for p in template.permissions if p.can_enroll or p.can_autoenroll}
    auth_capable = _has_client_auth(template.eku)
    broad_auth = auth_capable and ("authenticated users" in principals or "domain users" in principals)
    owner = (template.raw_json or {}).get("business_owner")
    return [
        _bp(
            "Templates",
            "Avoid broad enrollment on authentication templates",
            "Fail" if broad_auth else "Pass",
            "Critical" if broad_auth else "Low",
            template.name,
            {"eku": template.eku, "principals": list(principals)},
            "Broad enrollment on authentication templates can create enterprise identity risk.",
            "Low-privileged principals may obtain authentication-capable certificates if other safeguards are weak.",
            "Remove Authenticated Users / Domain Users from Enroll or AutoEnroll and scope to dedicated security groups.",
            "high",
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
            {"business_owner": owner},
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
    findings: list[Any],
) -> dict:
    items: list[dict] = []
    for ca in cas:
        items.extend(_ca_practices(ca))
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

    score, status, counts = _score(items)
    grouped: dict[str, list[dict]] = {}
    for item in items:
        grouped.setdefault(item["category"], []).append(item)
    return {"score": score, "status": status, "counts": counts, "items": items, "grouped": grouped}
