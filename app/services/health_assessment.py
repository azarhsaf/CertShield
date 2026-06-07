from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.models.entities import CertificateAuthority, CertificateTemplate, IssuedCertificate

HEALTH_STATUS_ORDER = {"Critical": 0, "Warning": 1, "Healthy": 2, "Not Assessed": 3, "Unknown": 4}


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M %p", "%m/%d/%Y"):
        try:
            return datetime.strptime(text[: len(fmt)], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _days_until(value: Any) -> int | None:
    dt = _parse_date(value)
    if not dt:
        return None
    return (dt - datetime.now(timezone.utc)).days


def _status_for_expiry(days: int | None) -> str:
    if days is None:
        return "Not Assessed"
    if days < 0:
        return "Critical"
    if days <= 30:
        return "Critical"
    if days <= 180:
        return "Warning"
    return "Healthy"


def _item(category: str, title: str, status: str, affected: str, evidence: dict, recommendation: str) -> dict:
    return {
        "category": category,
        "title": title,
        "status": status,
        "affected_object": affected,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _score(items: list[dict]) -> tuple[int | None, str]:
    assessed = [item for item in items if item["status"] not in {"Not Assessed", "Unknown"}]
    if not assessed:
        return None, "Unknown"
    score = 100
    for item in assessed:
        if item["status"] == "Critical":
            score -= 25
        elif item["status"] == "Warning":
            score -= 10
    score = max(score, 0)
    if score >= 90:
        return score, "Healthy"
    if score >= 70:
        return score, "Warning"
    if score >= 40:
        return score, "Degraded"
    return score, "Critical"


def assess_pki_health(
    cas: list[CertificateAuthority],
    templates: list[CertificateTemplate],
    certificates: list[IssuedCertificate],
    findings: list[Any],
    scan_completed_at: Any,
    collector_version: str,
    source_host: str,
) -> dict:
    items: list[dict] = []
    expiry_risks: list[dict] = []

    for ca in cas:
        config = ca.config_json or {}
        items.append(
            _item(
                "CA Service Health",
                "CA service query status",
                "Healthy" if ca.status.lower() == "online" else "Critical",
                ca.name,
                {"status": ca.status, "dns_name": ca.dns_name, "source_host": source_host},
                "Investigate CA service availability and collector reachability if status is not online.",
            )
        )

        ca_days = _days_until(config.get("certificate_expires_at") or config.get("ca_certificate_expires_at"))
        ca_status = _status_for_expiry(ca_days)
        items.append(
            _item(
                "CA Certificate Health",
                "CA certificate expiry",
                ca_status,
                ca.name,
                {
                    "expires_at": config.get("certificate_expires_at") or config.get("ca_certificate_expires_at"),
                    "days_remaining": ca_days,
                    "signature_algorithm": config.get("signature_algorithm"),
                    "key_size": config.get("key_size"),
                    "chain_complete": config.get("chain_complete", "Not Assessed"),
                },
                "Renew CA certificates before expiry and validate chain completeness, signature algorithm, and key size.",
            )
        )
        if ca_status in {"Critical", "Warning"}:
            expiry_risks.append({"type": "CA certificate", "ca": ca.name, "days_remaining": ca_days, "status": ca_status})

        for health_key, title, category, recommendation in (
            ("crl", "CRL publication and freshness", "CRL Health", "Publish valid CRLs at reachable CDP URLs and monitor nextUpdate values."),
            ("aia", "AIA chain retrieval", "AIA Health", "Publish reachable AIA URLs so clients can build certificate chains reliably."),
            ("ocsp", "OCSP responder status", "OCSP Health", "Assess OCSP responder configuration and OCSP signing certificate expiry where OCSP is used."),
        ):
            section = config.get(health_key, {}) if isinstance(config.get(health_key), dict) else {}
            assessed = section.get("assessed") or config.get(f"{health_key}_assessed")
            configured = section.get("configured") or config.get(f"{health_key}_configured")
            reachable = section.get("reachable") or config.get(f"{health_key}_reachable")
            expires_days = _days_until(section.get("expires_at") or section.get("next_update"))
            if assessed is not True and configured is None:
                status = "Not Assessed"
            elif configured is False:
                status = "Warning"
            elif reachable is False:
                status = "Critical"
            else:
                status = _status_for_expiry(expires_days) if expires_days is not None else "Healthy"
            items.append(_item(category, title, status, ca.name, {"configured": configured, "reachable": reachable, "days_remaining": expires_days, "details": section}, recommendation))
            if status in {"Critical", "Warning"}:
                expiry_risks.append({"type": category, "ca": ca.name, "days_remaining": expires_days, "status": status})

    cert_status = Counter(cert.status.lower() for cert in certificates)
    expired_certs = 0
    expiring_30 = 0
    expiring_60 = 0
    expiring_90 = 0
    for cert in certificates:
        days = _days_until(cert.expires_at)
        if days is None:
            continue
        if days < 0:
            expired_certs += 1
        if 0 <= days <= 30:
            expiring_30 += 1
        if 0 <= days <= 60:
            expiring_60 += 1
        if 0 <= days <= 90:
            expiring_90 += 1

    items.append(
        _item(
            "Certificate Issuance Health",
            "Issued certificate data collection",
            "Healthy" if certificates else "Warning",
            "Certificate database",
            {
                "issued": len(certificates),
                "failed": cert_status.get("failed", 0),
                "pending": cert_status.get("pending", 0),
                "expired": expired_certs,
                "expiring_30": expiring_30,
                "expiring_60": expiring_60,
                "expiring_90": expiring_90,
            },
            "Collect issued certificate inventory regularly and monitor failed, pending, expired, and soon-expiring certificates.",
        )
    )

    high_risk_templates = sum(1 for finding in findings if getattr(finding, "affected_object", None) in {t.name for t in templates} and getattr(finding, "severity", "") in {"Critical", "High"})
    not_fully_assessed = sum(1 for template in templates if not (template.raw_json or {}).get("acl_assessed"))
    items.append(
        _item(
            "Template Health",
            "Template inventory and assessment coverage",
            "Warning" if not_fully_assessed else "Healthy",
            "Certificate Templates",
            {"collected": len(templates), "high_risk_templates": high_risk_templates, "not_fully_assessed": not_fully_assessed, "enabled": len(templates), "disabled": 0},
            "Collect template ACL metadata where possible and prioritize remediation for high-risk authentication templates.",
        )
    )

    score, status = _score(items)
    counts = Counter(item["status"] for item in items)
    return {
        "score": score,
        "status": status,
        "counts": dict(counts),
        "collector": {"version": collector_version, "source_host": source_host, "last_successful_scan": str(scan_completed_at), "last_failed_scan": None},
        "items": items,
        "expiry_risks": expiry_risks,
        "recommendations": [item["recommendation"] for item in items if item["status"] in {"Critical", "Warning", "Not Assessed"}][:10],
    }
