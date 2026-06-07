from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.models.entities import CertificateAuthority, CertificateTemplate, IssuedCertificate

CRITICAL_HEALTH_CATEGORIES = {"CA Certificate Health", "CRL Health", "Certificate Issuance Health"}


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    for fmt in (
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M %p",
        "%m/%d/%Y",
    ):
        try:
            return datetime.strptime(text[: len(fmt)], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def _days_until(value: Any) -> int | None:
    dt = _parse_date(value)
    if not dt:
        return None
    return (dt - datetime.now(timezone.utc)).days


def _bool_text(value: Any) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Not collected"


def _list_value(*values: Any) -> list[Any]:
    for value in values:
        if isinstance(value, list) and value:
            return value
        if isinstance(value, str) and value.strip():
            return [value]
    return []


def _expiry_status(days: int | None, missing: str = "Not Assessed") -> str:
    if days is None:
        return missing
    if days < 0 or days <= 30:
        return "Critical"
    if days <= 90:
        return "Warning"
    return "Healthy"


def _item(
    category: str,
    title: str,
    status: str,
    affected: str,
    evidence: dict,
    recommendation: str,
    impact: str = "operational",
) -> dict:
    return {
        "category": category,
        "title": title,
        "status": status,
        "affected_object": affected,
        "evidence": evidence,
        "recommendation": recommendation,
        "impact": impact,
    }


def _score(items: list[dict]) -> tuple[int | None, str, list[str]]:
    if not items:
        return None, "Unknown", ["No health checks were produced from the latest scan."]

    score = 100
    explanations: list[str] = []
    assessed = [item for item in items if item["status"] not in {"Not Assessed", "Unknown"}]
    not_assessed = [item for item in items if item["status"] in {"Not Assessed", "Unknown"}]
    if not assessed:
        return None, "Unknown", ["Insufficient collected data to calculate PKI health."]

    for item in items:
        status = item["status"]
        category = item["category"]
        title = item["title"]
        if category == "CA Service Health" and status == "Critical":
            score -= 40
            explanations.append(f"-40: {title} is critical for {item['affected_object']}.")
        elif category == "CA Certificate Health" and status == "Critical":
            score -= 50
            explanations.append(f"-50: CA certificate is expired or expires within 30 days for {item['affected_object']}.")
        elif category == "CA Certificate Health" and status == "Warning":
            score -= 20
            explanations.append(f"-20: CA certificate expires within 90 days for {item['affected_object']}.")
        elif category == "CA Certificate Health" and status == "Not Assessed":
            score -= 15
            explanations.append(f"-15: CA certificate expiry was not assessed for {item['affected_object']}.")
        elif category == "CRL Health" and status == "Critical":
            score -= 50
            explanations.append(f"-50: CRL is expired or unreachable for {item['affected_object']}.")
        elif category == "CRL Health" and status == "Warning":
            score -= 25
            explanations.append(f"-25: CRL publication has a warning for {item['affected_object']}.")
        elif category == "CRL Health" and status == "Present / Not Tested":
            score -= 8
            explanations.append(f"-8: CRL path is present but reachability was not tested for {item['affected_object']}.")
        elif category == "CRL Health" and status == "Not Assessed":
            score -= 20
            explanations.append(f"-20: CRL/CDP freshness was not assessed for {item['affected_object']}.")
        elif category == "AIA Health" and status == "Critical":
            score -= 25
            explanations.append(f"-25: AIA retrieval appears unavailable for {item['affected_object']}.")
        elif category == "AIA Health" and status == "Warning":
            score -= 15
            explanations.append(f"-15: AIA configuration warning for {item['affected_object']}.")
        elif category == "AIA Health" and status == "Present / Not Tested":
            score -= 3
            explanations.append(f"-3: AIA URL is present but reachability was not tested for {item['affected_object']}.")
        elif category == "AIA Health" and status == "Not Assessed":
            score -= 10
            explanations.append(f"-10: AIA chain retrieval was not assessed for {item['affected_object']}.")
        elif category == "OCSP Health" and status == "Critical":
            score -= 20
            explanations.append(f"-20: OCSP responder has a critical status for {item['affected_object']}.")
        elif category == "OCSP Health" and status == "Warning":
            score -= 10
            explanations.append(f"-10: OCSP responder warning for {item['affected_object']}.")
        elif category == "OCSP Health" and status == "Not Assessed":
            score -= 5
            explanations.append(f"-5: OCSP posture was not assessed for {item['affected_object']}.")
        elif category == "Certificate Issuance Health" and status == "Warning":
            score -= 10
            explanations.append("-10: Issued certificate/request data was not collected or is empty.")
        elif category == "Template Health" and status == "Warning":
            score -= 10
            explanations.append("-10: Some template assessment coverage is incomplete.")

    not_assessed_ratio = len(not_assessed) / len(items)
    critical_not_assessed = [item for item in not_assessed if item["category"] in CRITICAL_HEALTH_CATEGORIES]
    if critical_not_assessed:
        penalty = min(25, 10 + (len(critical_not_assessed) * 5))
        score -= penalty
        explanations.append(f"-{penalty}: Critical health checks were not assessed.")
    limited_visibility = not_assessed_ratio > 0.5
    if limited_visibility or not_assessed_ratio > 0.4:
        score = min(score, 69)
        explanations.append("Score capped at 69 because more than 40% of health checks are Not Assessed.")
    if any(item["category"] == "CA Certificate Health" and item["status"] == "Not Assessed" for item in items):
        score = min(score, 79)
        explanations.append("Score capped at 79 because CA certificate expiry is Not Assessed.")
    if any(item["category"] == "CRL Health" and item["status"] == "Not Assessed" for item in items):
        score = min(score, 79)
        explanations.append("Score capped at 79 because CRL health is Not Assessed.")
    if any(item["category"] == "CRL Health" and item["status"] == "Critical" for item in items):
        score = min(score, 39)
        explanations.append("Score capped at 39 because CRL health is Critical.")

    score = max(0, min(100, score))
    if score >= 90 and not limited_visibility:
        return score, "Healthy", explanations
    if score >= 70:
        return score, "Warning", explanations
    if score >= 40:
        return score, "Degraded", explanations
    return score, "Critical", explanations


def _ca_certificate_item(ca: CertificateAuthority, config: dict) -> tuple[dict, dict | None]:
    cert = config.get("ca_certificate") if isinstance(config.get("ca_certificate"), dict) else {}
    expires_at = cert.get("not_after") or config.get("certificate_expires_at") or config.get("ca_certificate_expires_at")
    days = _days_until(expires_at)
    status = _expiry_status(days)
    evidence = {
        "expires_at": expires_at or "Not collected",
        "days_remaining": days if days is not None else "Not collected",
        "subject": cert.get("subject") or config.get("certificate_subject") or config.get("subject") or "Not collected",
        "issuer": cert.get("issuer") or config.get("certificate_issuer") or config.get("issuer") or "Not collected",
        "serial_number": cert.get("serial_number") or config.get("serial_number") or "Not collected",
        "thumbprint": cert.get("thumbprint") or config.get("thumbprint") or "Not collected",
        "not_before": cert.get("not_before") or config.get("certificate_not_before") or "Not collected",
        "signature_algorithm": cert.get("signature_algorithm") or config.get("signature_algorithm") or "Not collected",
        "key_size": cert.get("key_size") or config.get("key_size") or "Not collected",
        "chain_complete": _bool_text(cert.get("chain_complete") if "chain_complete" in cert else config.get("chain_complete")),
    }
    item = _item(
        "CA Certificate Health",
        "CA certificate expiry and chain evidence",
        status,
        ca.name,
        evidence,
        "Renew CA certificates before expiry and validate chain completeness, signature algorithm, and key size.",
        "validation",
    )
    risk = None
    if status in {"Critical", "Warning"}:
        risk = {"type": "CA certificate", "ca": ca.name, "days_remaining": days, "status": status}
    return item, risk


def _crl_item(ca: CertificateAuthority, config: dict) -> tuple[dict, dict | None]:
    section = config.get("crl") if isinstance(config.get("crl"), dict) else {}
    urls = _list_value(section.get("urls"), section.get("http_urls"), section.get("ldap_urls"), section.get("url"), config.get("crl_urls"), config.get("cdp_urls"))
    assessed = section.get("assessed") if "assessed" in section else config.get("crl_assessed")
    configured = section.get("configured") if "configured" in section else config.get("crl_configured")
    reachable = section.get("reachable") if "reachable" in section else config.get("crl_reachable")
    next_update = section.get("next_update") or section.get("expires_at") or config.get("crl_next_update")
    days = _days_until(next_update)

    if assessed is not True or (not urls and configured is not True):
        status = "Not Assessed"
    elif configured is False or not urls:
        status = "Warning"
    elif reachable is False or (days is not None and days < 0):
        status = "Critical"
    elif reachable is not True and days is not None and days >= 0:
        status = "Present / Not Tested"
    elif reachable is not True:
        status = "Not Assessed"
    elif days is not None and days <= 3:
        status = "Warning"
    elif days is None:
        status = "Not Assessed"
    else:
        status = "Healthy"

    evidence = {
        "crl_urls": urls or ["Not collected"],
        "http_urls": section.get("http_urls") or [],
        "ldap_urls": section.get("ldap_urls") or [],
        "reachable": _bool_text(reachable),
        "this_update": section.get("this_update") or "Not collected",
        "next_update": next_update or "Not collected",
        "days_remaining": days if days is not None else "Not collected",
        "tested_urls": section.get("tested_urls") or [],
        "errors": section.get("errors") or [],
        "delta_crl": _bool_text(section.get("delta_crl")),
        "source": section.get("source") or "Not collected",
    }
    item = _item(
        "CRL Health",
        "CRL/CDP publication and freshness",
        status,
        ca.name,
        evidence,
        "Publish valid CRLs at reachable CDP URLs and monitor nextUpdate values.",
        "validation",
    )
    risk = None
    if status in {"Critical", "Warning"}:
        risk = {"type": "CRL", "ca": ca.name, "days_remaining": days, "status": status}
    return item, risk


def _aia_item(ca: CertificateAuthority, config: dict) -> dict:
    section = config.get("aia") if isinstance(config.get("aia"), dict) else {}
    urls = _list_value(section.get("urls"), section.get("ca_issuer_urls"), section.get("url"), config.get("aia_urls"))
    assessed = section.get("assessed") if "assessed" in section else config.get("aia_assessed")
    configured = section.get("configured") if "configured" in section else config.get("aia_configured")
    reachable = section.get("reachable") if "reachable" in section else config.get("aia_reachable")
    chain_retrieval = section.get("chain_retrieval")

    if assessed is not True or (not urls and configured is not True):
        status = "Not Assessed"
    elif configured is False or not urls:
        status = "Warning"
    elif reachable is False or chain_retrieval is False:
        status = "Critical"
    elif reachable is not True and chain_retrieval is not True:
        status = "Present / Not Tested"
    else:
        status = "Healthy"

    return _item(
        "AIA Health",
        "AIA chain retrieval evidence",
        status,
        ca.name,
        {
            "aia_urls": urls or ["Not collected"],
            "ca_issuer_urls": section.get("ca_issuer_urls") or urls or [],
            "ocsp_urls": section.get("ocsp_urls") or [],
            "reachable": _bool_text(reachable),
            "chain_retrieval": _bool_text(chain_retrieval),
            "tested_urls": section.get("tested_urls") or [],
            "errors": section.get("errors") or [],
            "source": section.get("source") or "Not collected",
        },
        "Publish reachable AIA URLs so clients can build certificate chains reliably.",
        "validation",
    )


def _ocsp_item(ca: CertificateAuthority, config: dict) -> dict:
    section = config.get("ocsp") if isinstance(config.get("ocsp"), dict) else {}
    urls = _list_value(section.get("urls"), section.get("url"), config.get("ocsp_urls"))
    assessed = section.get("assessed") if "assessed" in section else config.get("ocsp_assessed")
    configured = section.get("configured") if "configured" in section else config.get("ocsp_configured")
    reachable = section.get("reachable") if "reachable" in section else config.get("ocsp_reachable")
    responder_status = section.get("responder_status") or section.get("status")
    signing_days = _days_until(section.get("signing_certificate_expires_at"))

    if assessed is not True or (not urls and configured is not True):
        status = "Not Assessed"
    elif configured is False:
        status = "Not Assessed"
    elif reachable is False or str(responder_status).lower() in {"failed", "offline", "critical"}:
        status = "Critical"
    elif reachable is not True:
        status = "Not Assessed"
    elif signing_days is not None and signing_days <= 30:
        status = "Warning"
    else:
        status = "Healthy"

    return _item(
        "OCSP Health",
        "OCSP responder status",
        status,
        ca.name,
        {
            "ocsp_urls": urls or ["Not configured / Not collected"],
            "reachable": _bool_text(reachable),
            "responder_status": responder_status or "Not collected",
            "signing_certificate_expires_at": section.get("signing_certificate_expires_at") or "Not collected",
            "signing_certificate_days_remaining": signing_days if signing_days is not None else "Not collected",
        },
        "Assess OCSP responder configuration and OCSP signing certificate expiry where OCSP is used.",
        "validation",
    )


def assess_pki_health(
    cas: list[CertificateAuthority],
    templates: list[CertificateTemplate],
    certificates: list[IssuedCertificate],
    findings: list[Any],
    scan_completed_at: Any,
    collector_version: str,
    source_host: str,
    health_coverage: dict | None = None,
) -> dict:
    items: list[dict] = []
    expiry_risks: list[dict] = []
    health_coverage = health_coverage or {}

    for ca in cas:
        config = ca.config_json or {}
        ca_status_text = str(ca.status or "").lower()
        if ca_status_text in {"", "unknown", "not_collected", "not assessed"}:
            service_status = "Not Assessed"
        elif ca_status_text == "online":
            service_status = "Healthy"
        else:
            service_status = "Critical"
        items.append(
            _item(
                "CA Service Health",
                "CA service query status",
                service_status,
                ca.name,
                {"status": ca.status or "Not collected", "dns_name": ca.dns_name or "Not collected", "source_host": source_host or "Not collected"},
                "Investigate CA service availability and collector reachability if status is not online.",
                "availability",
            )
        )

        ca_cert_item, ca_cert_risk = _ca_certificate_item(ca, config)
        items.append(ca_cert_item)
        if ca_cert_risk:
            expiry_risks.append(ca_cert_risk)

        crl_item, crl_risk = _crl_item(ca, config)
        items.append(crl_item)
        if crl_risk:
            expiry_risks.append(crl_risk)
        items.append(_aia_item(ca, config))
        items.append(_ocsp_item(ca, config))

    cert_status = Counter((cert.status or "unknown").lower() for cert in certificates)
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

    issued_collected = health_coverage.get("issued_certificates_collected")
    if certificates:
        issuance_status = "Healthy"
        collection_status = "Collected"
    elif issued_collected is False:
        issuance_status = "Not Assessed"
        collection_status = health_coverage.get("issued_certificates_reason") or "Skipped, failed, or not available"
    else:
        issuance_status = "Warning"
        collection_status = "No issued certificate rows returned"
    items.append(
        _item(
            "Certificate Issuance Health",
            "Issued certificate/request data collection",
            issuance_status,
            "Certificate database",
            {
                "collection_status": collection_status,
                "issued": len(certificates),
                "failed": cert_status.get("failed", 0),
                "pending": cert_status.get("pending", 0),
                "expired": expired_certs,
                "expiring_30": expiring_30,
                "expiring_60": expiring_60,
                "expiring_90": expiring_90,
            },
            "Collect issued certificate inventory regularly and monitor failed, pending, expired, and soon-expiring certificates.",
            "availability",
        )
    )

    template_names = {t.name for t in templates}
    high_risk_templates = sum(
        1
        for finding in findings
        if getattr(finding, "affected_object", None) in template_names and getattr(finding, "severity", "") in {"Critical", "High"}
    )
    not_fully_assessed = sum(1 for template in templates if not (template.raw_json or {}).get("acl_assessed"))
    items.append(
        _item(
            "Template Health",
            "Template inventory and assessment coverage",
            "Warning" if not_fully_assessed else "Healthy",
            "Certificate Templates",
            {
                "collected": len(templates),
                "high_risk_templates": high_risk_templates,
                "not_fully_assessed": not_fully_assessed,
                "enabled": len(templates),
                "disabled": 0,
            },
            "Collect template ACL metadata where possible and prioritize remediation for high-risk authentication templates.",
            "coverage",
        )
    )

    score, status, explanations = _score(items)
    counts = Counter(item["status"] for item in items)
    limited_visibility = bool(items) and counts.get("Not Assessed", 0) / len(items) > 0.4
    return {
        "score": score,
        "status": "Limited Visibility" if limited_visibility and status != "Unknown" else status,
        "limited_visibility": limited_visibility,
        "score_explanation": explanations,
        "counts": dict(counts),
        "collector": {
            "version": collector_version,
            "source_host": source_host,
            "last_successful_scan": str(scan_completed_at),
            "last_failed_scan": None,
        },
        "items": items,
        "expiry_risks": expiry_risks,
        "recommendations": [
            item["recommendation"] for item in items if item["status"] in {"Critical", "Warning", "Not Assessed"}
        ][:10],
    }
