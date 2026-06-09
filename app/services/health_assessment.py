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


def _errors(section: dict) -> list[str]:
    value = section.get("errors") or section.get("error") or []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if str(value).strip():
        return [str(value)]
    return []


def _reason(*values: Any, default: str) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value
    return default


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


def _score(items: list[dict]) -> tuple[int | None, str, list[str], str, int, list[str]]:
    if not items:
        return None, "Unknown", ["No health checks were produced from the latest scan."], "Unknown", 0, []

    category_weights = {
        "CA Service Health": 15,
        "CA Certificate Health": 20,
        "CRL Health": 25,
        "AIA Health": 15,
        "OCSP Health": 5,
        "Certificate Issuance Health": 10,
        "Template Health": 5,
        "Collector Coverage": 5,
    }
    status_points = {
        "Healthy": 100,
        "Present / Not Tested": 70,
        "Not Configured": 65,
        "Warning": 55,
        "Degraded": 40,
        "Critical": 0,
        "Not Assessed": None,
        "Unknown": None,
    }
    explanations: list[str] = []
    top_factors: list[str] = []
    assessed_weight = 0
    weighted_points = 0
    total_weight = sum(category_weights.values())
    category_scores: dict[str, list[int]] = {}

    for item in items:
        category = item["category"]
        weight = category_weights.get(category, 5)
        points = status_points.get(item["status"], 50)
        if points is None:
            top_factors.append(f"{category} for {item['affected_object']} is Not Assessed.")
            continue
        assessed_weight += weight
        weighted_points += weight * points
        category_scores.setdefault(category, []).append(points)
        if points < 70:
            top_factors.append(f"{category} for {item['affected_object']} is {item['status']}.")

    if assessed_weight == 0:
        return None, "Unknown", ["No meaningful CA certificate, CRL, AIA, OCSP, or issuance evidence was collected."], "Unknown", 0, top_factors[:8]

    score = round(weighted_points / assessed_weight)
    coverage = round(assessed_weight * 100 / total_weight)
    confidence = "High" if coverage >= 80 else "Medium" if coverage >= 50 else "Low"
    explanations.append(
        f"Weighted health score uses collected categories only; scan coverage is {coverage}% with {confidence} confidence."
    )

    ca_cert_items = [item for item in items if item["category"] == "CA Certificate Health"]
    crl_items = [item for item in items if item["category"] == "CRL Health"]
    if ca_cert_items and sum(1 for item in ca_cert_items if item["status"] == "Not Assessed") / len(ca_cert_items) > 0.5:
        score = min(score, 60)
        explanations.append("Score capped at 60 because CA certificate metadata is missing for most CAs.")
    if crl_items and sum(1 for item in crl_items if item["status"] == "Not Assessed") / len(crl_items) > 0.5:
        score = min(score, 70)
        explanations.append("Score capped at 70 because CRL evidence is missing for most CAs.")
    if any(item["category"] == "CRL Health" and item["status"] == "Critical" for item in items):
        score = min(score, 40)
        explanations.append("Score capped at 40 because a CRL is expired or unreachable.")
    if any(item["category"] == "CA Certificate Health" and item["status"] == "Critical" for item in items):
        score = min(score, 30)
        explanations.append("Score capped at 30 because a CA certificate is expired or near expiry.")
    if coverage < 50:
        score = min(score, 74)
        explanations.append("Score capped below Good because less than half of weighted health evidence was collected.")

    if score >= 90:
        status = "Excellent"
    elif score >= 75:
        status = "Good"
    elif score >= 60:
        status = "Needs Attention"
    elif score >= 40:
        status = "Poor"
    else:
        status = "Critical"
    return max(0, min(100, score)), status, explanations, confidence, coverage, top_factors[:8]


def _ca_certificate_item(ca: CertificateAuthority, config: dict) -> tuple[dict, dict | None]:
    cert = config.get("ca_certificate") if isinstance(config.get("ca_certificate"), dict) else {}
    expires_at = cert.get("not_after") or config.get("certificate_expires_at") or config.get("ca_certificate_expires_at")
    days = _days_until(expires_at)
    status = _expiry_status(days)
    certificate_collected = config.get("certificate_collected") is True or bool(cert)
    collection_reason = _reason(
        config.get("certificate_collection_reason"),
        cert.get("collection_reason"),
        default=(
            "Collected by the Windows collector with certutil -config <CAHost\\CAName> -ca.cert."
            if certificate_collected
            else "Not collected. Run the current Windows collector from a host that can query the CA; it uses certutil -ca.cert."
        ),
    )
    evidence = {
        "assessment_result": status,
        "collection_source": "ADCS certutil -ca.cert / normalized ca_certificate payload",
        "collector_command": "certutil -config <CAHost\\CAName> -ca.cert <file>",
        "collection_reason": collection_reason,
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
        "how_to_collect": "Run collector/windows/Collect-AdcsData.ps1 without -SkipHealth from a domain-joined host with certutil access to the CA.",
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
    urls = _list_value(
        section.get("urls"),
        section.get("http_urls"),
        section.get("ldap_urls"),
        section.get("url"),
        config.get("crl_urls"),
        config.get("cdp_urls"),
    )
    assessed = section.get("assessed") if "assessed" in section else config.get("crl_assessed")
    configured = section.get("configured") if "configured" in section else config.get("crl_configured")
    reachable = section.get("reachable") if "reachable" in section else config.get("crl_reachable")
    next_update = section.get("next_update") or section.get("expires_at") or config.get("crl_next_update")
    days = _days_until(next_update)
    errors = _errors(section)
    reason = _reason(
        section.get("reason"),
        section.get("collection_reason"),
        default="CRL evidence is extracted from the CA certificate CDP extension and ADCS CA registry values.",
    )

    if assessed is not True and not urls:
        status = "Not Assessed"
        reason = _reason(
            section.get("reason"),
            section.get("collection_reason"),
            default="Collector did not provide CRL/CDP URLs or freshness data. Run the collector without -SkipHealth/-SkipCrl.",
        )
    elif configured is False or not urls:
        status = "Warning"
        reason = _reason(section.get("reason"), default="No CRL/CDP URL was configured or extracted from the CA certificate/registry.")
    elif reachable is False:
        status = "Critical"
        reason = _reason(section.get("reason"), default="At least one HTTP CRL URL was tested and was not reachable.")
    elif days is not None and days < 0:
        status = "Critical"
        reason = _reason(section.get("reason"), default="The CRL nextUpdate value is in the past.")
    elif reachable is True and days is not None and days <= 3:
        status = "Warning"
        reason = _reason(section.get("reason"), default="The CRL is reachable but expires within three days.")
    elif reachable is True and days is not None:
        status = "Healthy"
        reason = _reason(section.get("reason"), default="HTTP CRL was fetched successfully and nextUpdate is in the future.")
    elif reachable is not True and days is not None and days >= 0:
        status = "Present / Not Tested"
        reason = _reason(section.get("reason"), default="CRL/CDP path and freshness were collected, but reachability was not confirmed.")
    else:
        status = "Not Assessed"
        reason = _reason(section.get("reason"), default="CRL URL exists, but freshness/reachability was not collected or parsed.")

    evidence = {
        "assessment_result": status,
        "collection_source": section.get("source") or "CA certificate CDP extension, ADCS CA registry, and HTTP CRL fetch",
        "collector_commands": [
            "certutil -config <CAHost\\CAName> -ca.cert <file>",
            "certutil -config <CAHost\\CAName> -getreg CA\\CRLPublicationURLs",
            "HTTP GET for CRL URLs when present",
        ],
        "reason": reason,
        "crl_urls": urls or ["Not collected"],
        "http_urls": section.get("http_urls") or [],
        "ldap_urls": section.get("ldap_urls") or [],
        "reachable": _bool_text(reachable),
        "this_update": section.get("this_update") or "Not collected",
        "next_update": next_update or "Not collected",
        "days_remaining": days if days is not None else "Not collected",
        "tested_urls": section.get("tested_urls") or [],
        "errors": errors or ["None recorded"],
        "delta_crl": _bool_text(section.get("delta_crl")),
        "how_to_collect": "Run the Windows collector without -SkipCrl. Ensure the collector host can reach HTTP CDP URLs if reachability should be tested.",
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
    errors = _errors(section)
    reason = _reason(
        section.get("reason"),
        section.get("collection_reason"),
        default="AIA evidence is extracted from the CA certificate AIA extension and ADCS CA registry values.",
    )

    if assessed is not True and not urls:
        status = "Not Assessed"
        reason = _reason(section.get("reason"), default="Collector did not provide AIA URLs. Run the collector without -SkipHealth.")
    elif configured is False or not urls:
        status = "Warning"
        reason = _reason(section.get("reason"), default="No AIA CA issuer URL was configured or extracted.")
    elif reachable is False or chain_retrieval is False:
        status = "Critical"
        reason = _reason(section.get("reason"), default="An AIA URL was tested and was not reachable.")
    elif reachable is not True and chain_retrieval is not True:
        status = "Present / Not Tested"
        reason = _reason(section.get("reason"), default="AIA URL is present, but chain retrieval/reachability was not confirmed.")
    else:
        status = "Healthy"
        reason = _reason(section.get("reason"), default="AIA URL was collected and reachability/chain retrieval evidence is healthy.")

    return _item(
        "AIA Health",
        "AIA chain retrieval evidence",
        status,
        ca.name,
        {
            "assessment_result": status,
            "collection_source": section.get("source") or "CA certificate AIA extension, ADCS CA registry, and HTTP AIA fetch",
            "collector_commands": [
                "certutil -config <CAHost\\CAName> -ca.cert <file>",
                "certutil -config <CAHost\\CAName> -getreg CA\\CACertPublicationURLs",
                "HTTP GET for AIA CA issuer URLs when present",
            ],
            "reason": reason,
            "aia_urls": urls or ["Not collected"],
            "ca_issuer_urls": section.get("ca_issuer_urls") or urls or [],
            "ocsp_urls": section.get("ocsp_urls") or [],
            "reachable": _bool_text(reachable),
            "chain_retrieval": _bool_text(chain_retrieval),
            "tested_urls": section.get("tested_urls") or [],
            "errors": errors or ["None recorded"],
            "how_to_collect": "Run the Windows collector without -SkipHealth. Ensure HTTP AIA URLs are reachable from the collector if reachability should be tested.",
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
    errors = _errors(section)

    if assessed is not True and not urls:
        status = "Not Assessed"
        reason = _reason(section.get("reason"), default="Collector did not provide OCSP responder URL evidence.")
    elif configured is False or not urls:
        status = "Not Configured"
        reason = _reason(section.get("reason"), default="No OCSP URL was present in AIA. OCSP may be intentionally unused, but it is not healthy evidence.")
    elif reachable is False or str(responder_status).lower() in {"failed", "offline", "critical"}:
        status = "Critical"
        reason = _reason(section.get("reason"), default="OCSP responder URL was present but reachability/status check failed.")
    elif reachable is not True:
        status = "Present / Not Tested"
        reason = _reason(section.get("reason"), default="OCSP URL is present, but responder reachability was not confirmed.")
    elif signing_days is not None and signing_days <= 30:
        status = "Warning"
        reason = _reason(section.get("reason"), default="OCSP responder is reachable but signing certificate expires soon.")
    else:
        status = "Healthy"
        reason = _reason(section.get("reason"), default="OCSP URL was present and reachable from the collector.")

    return _item(
        "OCSP Health",
        "OCSP responder status",
        status,
        ca.name,
        {
            "assessment_result": status,
            "collection_source": section.get("source") or "OCSP URLs from AIA extension with HTTP reachability probe",
            "reason": reason,
            "ocsp_urls": urls or ["Not configured / Not collected"],
            "reachable": _bool_text(reachable),
            "responder_status": responder_status or "Not collected",
            "tested_urls": section.get("tested_urls") or [],
            "errors": errors or ["None recorded"],
            "signing_certificate_expires_at": section.get("signing_certificate_expires_at") or "Not collected",
            "signing_certificate_days_remaining": signing_days if signing_days is not None else "Not collected",
            "how_to_collect": "OCSP URLs are extracted from AIA. If you use OCSP, make sure the URL is in the CA certificate AIA extension and reachable from the collector.",
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
    issued_count = health_coverage.get("issued_certificates_count", len(certificates))
    issued_reason = health_coverage.get("issued_certificates_reason")
    issued_error = health_coverage.get("issued_certificates_error")
    queried_cas = health_coverage.get("issued_certificates_queried_cas") or []
    if certificates:
        issuance_status = "Healthy"
        collection_status = "Collected"
        collection_reason = _reason(issued_reason, default="Collector parsed issued certificate rows from the CA database.")
    elif issued_collected is False:
        issuance_status = "Not Assessed"
        collection_status = "Not collected"
        collection_reason = _reason(
            issued_error,
            issued_reason,
            default="Collector skipped or failed issued certificate enumeration.",
        )
    elif issued_collected is True:
        issuance_status = "Warning"
        collection_status = "Collected zero rows"
        collection_reason = _reason(
            issued_reason,
            default="Collector queried the CA database successfully, but certutil returned zero issued rows for the configured restriction/window.",
        )
    else:
        issuance_status = "Not Assessed"
        collection_status = "No collector status"
        collection_reason = "The collector payload did not include issued certificate collection status. Run the current collector without -SkipIssued."
    items.append(
        _item(
            "Certificate Issuance Health",
            "Issued certificate/request data collection",
            issuance_status,
            "Certificate database",
            {
                "assessment_result": issuance_status,
                "collection_status": collection_status,
                "collection_reason": collection_reason,
                "collector_command": "certutil -config <CAHost\\CAName> -view -restrict Disposition=20 -out RequestID,RequesterName,CertificateTemplate,CommonName,NotBefore,NotAfter",
                "required_access": "Run as an account that can read the CA database/view issued requests on each CA.",
                "queried_cas": queried_cas or ["Not collected"],
                "records_reported_by_collector": issued_count,
                "records_stored": len(certificates),
                "issued": len(certificates),
                "failed": cert_status.get("failed", 0),
                "pending": cert_status.get("pending", 0),
                "expired": expired_certs,
                "expiring_30": expiring_30,
                "expiring_60": expiring_60,
                "expiring_90": expiring_90,
                "how_to_collect": "Run collector/windows/Collect-AdcsData.ps1 without -SkipIssued from a CA admin workstation or CA server where certutil -view works for the selected account.",
                "errors": [issued_error] if issued_error else ["None recorded"],
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

    score, status, explanations, confidence, coverage_score, top_factors = _score(items)
    counts = Counter(item["status"] for item in items)
    limited_visibility = bool(items) and counts.get("Not Assessed", 0) / len(items) > 0.4
    return {
        "score": score,
        "status": "Limited Visibility" if limited_visibility and status != "Unknown" else status,
        "limited_visibility": limited_visibility,
        "grade": status,
        "confidence": confidence,
        "coverage": coverage_score,
        "score_explanation": explanations,
        "top_factors": top_factors,
        "why": "Operational health is weighted across CA availability, certificate validity, CRL freshness, AIA chain publication, OCSP, issuance data, and collector coverage.",
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
