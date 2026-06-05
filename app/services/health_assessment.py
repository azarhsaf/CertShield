from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.models.entities import CertificateAuthority, CertificateTemplate


@dataclass
class HealthAssessmentItem:
    category: str
    title: str
    status: str
    severity: str
    affected_object: str
    evidence: dict
    recommendation: str
    confidence: str


def _config(ca: CertificateAuthority) -> dict:
    return ca.config_json or {}


def _nested(mapping: dict, *keys: str) -> Any:
    cur: Any = mapping
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y", "%m/%d/%Y %I:%M:%S %p"):
        try:
            return datetime.strptime(text[: len(fmt)], fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


def _item(category: str, title: str, status: str, severity: str, affected_object: str, evidence: dict, recommendation: str, confidence: str = "medium") -> HealthAssessmentItem:
    return HealthAssessmentItem(
        category=category,
        title=title,
        status=status,
        severity=severity,
        affected_object=affected_object,
        evidence=evidence,
        recommendation=recommendation,
        confidence=confidence,
    )


def _date_health(category: str, title: str, affected_object: str, value: Any, warning_days: int, critical_when_expired: bool, recommendation: str) -> HealthAssessmentItem:
    parsed = _parse_date(value)
    if not parsed:
        return _item(category, f"{title} not assessed", "Unknown", "Info", affected_object, {"value": value}, recommendation, "low")
    days_remaining = (parsed - datetime.utcnow()).days
    evidence = {"not_after_or_next_update": parsed.date().isoformat(), "days_remaining": days_remaining}
    if critical_when_expired and days_remaining < 0:
        return _item(category, f"{title} is expired", "Critical", "Critical", affected_object, evidence, recommendation, "high")
    if days_remaining <= warning_days:
        return _item(category, f"{title} expires soon", "Warning", "Medium", affected_object, evidence, recommendation, "high")
    return _item(category, f"{title} is current", "Healthy", "Info", affected_object, evidence, "Continue monitoring this date on each scan.", "high")


def _template_is_dangerous(template: CertificateTemplate) -> bool:
    eku = " ".join(template.eku or []).lower()
    has_client_auth = "client authentication" in eku or "1.3.6.1.5.5.7.3.2" in eku
    broad_enroll = any((p.can_enroll or p.can_autoenroll) and p.principal.lower() in {"authenticated users", "domain users", "everyone"} for p in template.permissions)
    return has_client_auth and broad_enroll and template.enrollee_supplies_subject and not template.manager_approval


def _cert_expiry_items(certificates: list[Any]) -> list[HealthAssessmentItem]:
    if not certificates:
        return [
            _item(
                "Certificate Inventory",
                "Issued certificate inventory not collected",
                "Unknown",
                "Info",
                "Issued certificate database",
                {"certificates_seen": 0},
                "Run the collector without -SkipIssued when operationally acceptable, or import issued certificate inventory through a future supported connector.",
                "medium",
            )
        ]
    items: list[HealthAssessmentItem] = []
    expired = 0
    expiring = 0
    for cert in certificates:
        expires = _parse_date(getattr(cert, "expires_at", ""))
        if not expires:
            continue
        days_remaining = (expires - datetime.utcnow()).days
        if days_remaining < 0:
            expired += 1
        elif days_remaining <= 30:
            expiring += 1
    if expired:
        items.append(
            _item(
                "Certificate Lifecycle",
                "Expired issued certificates observed",
                "Warning",
                "Medium",
                "Issued certificates",
                {"expired_count": expired},
                "Review expired certificates and remove, renew, or document them according to certificate lifecycle policy.",
                "medium",
            )
        )
    if expiring:
        items.append(
            _item(
                "Certificate Lifecycle",
                "Issued certificates expire within 30 days",
                "Warning",
                "Medium",
                "Issued certificates",
                {"expiring_30_days": expiring},
                "Prioritize renewal or decommissioning for certificates approaching expiry.",
                "medium",
            )
        )
    if not items:
        items.append(
            _item(
                "Certificate Lifecycle",
                "Issued certificate expiry posture is healthy",
                "Healthy",
                "Info",
                "Issued certificates",
                {"certificates_seen": len(certificates)},
                "Continue regular certificate lifecycle monitoring.",
                "medium",
            )
        )
    return items


def assess_pki_health(
    cas: list[CertificateAuthority],
    templates: list[CertificateTemplate],
    certificates: list[Any],
    assessment_hints: dict | None = None,
) -> tuple[list[HealthAssessmentItem], dict]:
    hints = assessment_hints or {}
    items: list[HealthAssessmentItem] = []

    if cas:
        items.append(
            _item(
                "Inventory",
                "Enterprise CAs collected",
                "Healthy",
                "Info",
                "PKI inventory",
                {"ca_count": len(cas)},
                "Continue collecting CA inventory each scan.",
                "high",
            )
        )
    else:
        items.append(
            _item(
                "Inventory",
                "No Enterprise CAs collected",
                "Critical",
                "High",
                "PKI inventory",
                {"ca_count": 0},
                "Verify collector permissions and certutil availability so CA inventory can be assessed.",
                "high",
            )
        )

    dangerous_templates = [t.name for t in templates if _template_is_dangerous(t)]
    items.append(
        _item(
            "Template Risk",
            "Dangerous template count calculated",
            "Warning" if dangerous_templates else "Healthy",
            "High" if dangerous_templates else "Info",
            "Certificate templates",
            {"dangerous_template_count": len(dangerous_templates), "templates": dangerous_templates},
            "Review dangerous templates first because they create the clearest certificate exposure paths.",
            "high",
        )
    )

    failed_count = sum(1 for c in certificates if str(getattr(c, "status", "")).lower() == "failed")
    pending_count = sum(1 for c in certificates if str(getattr(c, "status", "")).lower() == "pending")
    recently_issued = sum(1 for c in certificates if str(getattr(c, "status", "issued")).lower() == "issued")
    items.append(
        _item(
            "Request Volume",
            "Certificate request status summarized",
            "Warning" if failed_count or pending_count else "Healthy",
            "Medium" if failed_count else "Low" if pending_count else "Info",
            "CA request database",
            {"failed": failed_count, "pending": pending_count, "recently_issued": recently_issued},
            "Review failed and pending requests for operational issues, policy drift, or stalled approvals.",
            "medium" if certificates else "low",
        )
    )

    for ca in cas:
        config = _config(ca)
        name = ca.name
        service_status = config.get("service_status")
        if service_status:
            healthy = str(service_status).lower() in {"running", "online", "started"}
            items.append(
                _item(
                    "CA Service",
                    "CA service is running" if healthy else "CA service is not running",
                    "Healthy" if healthy else "Critical",
                    "Info" if healthy else "Critical",
                    name,
                    {"service_status": service_status},
                    "Investigate CA service availability and restart only through approved operational procedures." if not healthy else "Continue monitoring CA service state.",
                    "medium",
                )
            )
        else:
            items.append(_item("CA Service", "CA service status not assessed", "Unknown", "Info", name, {}, "Collect CA service status where the collector has sufficient local visibility.", "low"))

        ca_expiry = config.get("certificate_not_after") or _nested(config, "certificate", "not_after") or config.get("not_after")
        items.append(_date_health("CA Certificate", "CA certificate", name, ca_expiry, 90, True, "Renew or replace CA certificates before expiry using approved PKI change procedures."))

        crl_next = config.get("crl_next_update") or _nested(config, "crl", "next_update")
        items.append(_date_health("CRL", "CRL", name, crl_next, 7, True, "Publish a fresh CRL and verify CDP publication before clients depend on stale revocation data."))

        for url_type, key in (("AIA", "aia_urls"), ("CDP", "cdp_urls")):
            urls = config.get(key) or _nested(config, "certificate", key)
            if urls is None:
                items.append(_item(url_type, f"{url_type} URL reachability not assessed", "Unknown", "Info", name, {}, f"Collect and validate {url_type} publication URLs during the next collector enhancement.", "low"))
            elif not urls:
                items.append(_item(url_type, f"{url_type} URL missing", "Warning", "Medium", name, {key: urls}, f"Publish valid {url_type} locations so clients can build and validate certificate chains reliably.", "medium"))
            else:
                reachable = config.get(f"{key}_reachable")
                status = "Healthy" if reachable is not False else "Warning"
                items.append(_item(url_type, f"{url_type} URLs collected", status, "Info" if status == "Healthy" else "Medium", name, {key: urls, "reachable": reachable}, f"Verify {url_type} URLs remain reachable from relying systems.", "medium"))

        ocsp = config.get("ocsp_status") or _nested(config, "ocsp", "status") or hints.get("ocsp_status")
        if ocsp:
            healthy = str(ocsp).lower() in {"healthy", "online", "ok"}
            items.append(_item("OCSP", "OCSP status assessed", "Healthy" if healthy else "Warning", "Info" if healthy else "Medium", name, {"ocsp_status": ocsp}, "Review OCSP service state if deployed and required by relying parties.", "medium"))
        else:
            items.append(_item("OCSP", "OCSP not assessed", "Unknown", "Info", name, {}, "Collect OCSP responder status where deployed; otherwise document that OCSP is not used.", "low"))

    items.extend(_cert_expiry_items(certificates))

    counts: dict[str, int] = {}
    for item in items:
        counts[item.status] = counts.get(item.status, 0) + 1
    score = max(0, 100 - counts.get("Critical", 0) * 25 - counts.get("Warning", 0) * 10 - counts.get("Unknown", 0) * 3)
    if score >= 85:
        overall = "Healthy"
    elif score >= 60:
        overall = "Warning"
    else:
        overall = "Critical"
    summary = {
        "score": score,
        "status": overall,
        "counts": counts,
        "ca_count": len(cas),
        "template_count": len(templates),
        "dangerous_template_count": len(dangerous_templates),
        "failed_request_count": failed_count,
        "pending_request_count": pending_count,
        "recently_issued_count": recently_issued,
    }
    return items, summary
