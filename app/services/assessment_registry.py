from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import Any, Iterable

from app.models.entities import CertificateAuthority, CertificateTemplate, Finding, IssuedCertificate, RiskAcceptance
from app.services.pki_hierarchy import build_pki_hierarchy, ca_certificate, ca_role, key_protection
from app.services.risk_acceptance import acceptance_is_active, finding_fingerprint

OPEN_DEDUCTIONS = {"Critical": 25, "High": 15, "Medium": 7, "Low": 3}
ACCEPTED_DEDUCTIONS = {"Critical": 5, "High": 3, "Medium": 1, "Low": 0}
CATEGORY_CAPS = {
    "CA Health": 40,
    "Template Risk": 35,
    "Best Practices": 25,
    "Coverage Gaps": 20,
}

COVERAGE_GAP_STATUSES = {
    "Not Assessed",
    "Unknown",
    "Evidence Missing",
    "Present / Not Tested",
}

CONFIRMED_RISK_STATUSES = {
    "Critical",
    "High Risk",
    "Fail",
    "Warning",
    "Needs Attention",
}


def _is_coverage_gap(record: dict[str, Any]) -> bool:
    return record.get("original_status") in COVERAGE_GAP_STATUSES


def _is_confirmed_risk(record: dict[str, Any]) -> bool:
    return (
        record.get("severity") in {"Critical", "High"}
        and record.get("original_status") in CONFIRMED_RISK_STATUSES
    )


def registry_fingerprint(category: str, object_type: str, object_name: str, title: str) -> str:
    normalized = "|".join(
        str(part).strip().lower()
        for part in (category, object_type, object_name, title)
        if str(part).strip()
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _acceptance_status(fingerprint: str, acceptances: dict[str, RiskAcceptance]) -> tuple[bool, int | None, str]:
    acceptance = acceptances.get(fingerprint)
    if not acceptance:
        return False, None, "open"
    if acceptance_is_active(acceptance):
        return True, acceptance.id, "active"
    return False, acceptance.id, "expired"


def _record(
    *,
    object_type: str,
    object_name: str,
    category: str,
    title: str,
    status: str,
    severity: str,
    confidence: str,
    source: str,
    evidence: dict[str, Any],
    recommendation: str,
    acceptances: dict[str, RiskAcceptance],
    fingerprint: str | None = None,
    related_ca: str = "",
    related_template: str = "",
    related_finding: int | None = None,
) -> dict[str, Any]:
    fingerprint = fingerprint or registry_fingerprint(category, object_type, object_name, title)
    accepted, acceptance_id, acceptance_status = _acceptance_status(fingerprint, acceptances)
    return {
        "object_type": object_type,
        "object_name": object_name,
        "category": category,
        "title": title,
        "status": "Accepted Risk" if accepted else status,
        "original_status": status,
        "severity": severity,
        "confidence": confidence,
        "source": source,
        "evidence": evidence,
        "recommendation": recommendation,
        "fingerprint": fingerprint,
        "related_ca": related_ca,
        "related_template": related_template,
        "related_finding": related_finding,
        "accepted_risk": accepted,
        "acceptance_id": acceptance_id,
        "acceptance_status": acceptance_status,
    }


def _severity_from_status(status: str, default: str = "Medium") -> str:
    if status in {"Critical", "High Risk", "Fail"}:
        return "Critical" if status == "Critical" else "High"
    if status in {"Warning", "Needs Attention", "Present / Not Tested", "Not Assessed"}:
        return "Medium"
    return default


def _coverage_level(records: list[dict[str, Any]]) -> tuple[int, str, list[str]]:
    assessed = [r for r in records if r["original_status"] not in {"Not Assessed", "Unknown", "Evidence Missing"}]
    if not records:
        return 0, "Unknown / Not Enough Data", ["No assessment evidence was collected yet."]
    pct = round(len(assessed) * 100 / len(records))
    label = "Excellent" if pct >= 90 else "Good" if pct >= 75 else "Needs Attention" if pct >= 60 else "High Risk" if pct >= 40 else "Unknown / Not Enough Data"
    gaps = [f"{r['category']}: {r['title']} for {r['object_name']}" for r in records if r["original_status"] in {"Not Assessed", "Unknown", "Evidence Missing"}]
    return pct, label, gaps[:5]


def _assurance(records: list[dict[str, Any]], hierarchy: dict[str, Any]) -> dict[str, Any]:
    meaningful = [r for r in records if r["object_type"] != "pki_hierarchy"]
    if not meaningful:
        return {
            "score": None,
            "assurance_level": "Unknown / Not Enough Data",
            "coverage_score": 0,
            "coverage_level": "Unknown / Not Enough Data",
            "open_risk_count": 0,
            "accepted_risk_count": 0,
            "open_critical": 0,
            "open_high": 0,
            "why": ["No meaningful evidence was collected yet."],
            "accepted_reasons": [],
            "coverage_gaps": ["Run a collector scan to populate PKI evidence."],
        }

    caps = Counter()
    open_counts = Counter()
    accepted_counts = Counter()
    open_reasons: list[str] = []
    accepted_reasons: list[str] = []
    for record in meaningful:
        severity = record["severity"]
        if severity not in OPEN_DEDUCTIONS:
            continue
        if record["accepted_risk"] and _is_confirmed_risk(record):
            accepted_counts[severity] += 1
            caps[record["category"]] += ACCEPTED_DEDUCTIONS[severity]
            accepted_reasons.append(
                f"{severity} accepted by policy: {record['title']} ({record['object_name']})."
            )
        elif _is_confirmed_risk(record):
            open_counts[severity] += 1
            caps[record["category"]] += OPEN_DEDUCTIONS[severity]
            open_reasons.append(
                f"{severity} confirmed: {record['title']} ({record['object_name']})."
            )

    category_deduction = 0
    for category, amount in caps.items():
        cap = CATEGORY_CAPS.get(category, 20)
        category_deduction += min(cap, amount)
    score = max(0, min(100, 100 - category_deduction))
    coverage_score, coverage_level, coverage_gaps = _coverage_level(meaningful)
    if coverage_score == 0:
        assurance_level = "Unknown / Not Enough Data"
        score = None
    elif score >= 90:
        assurance_level = "Excellent"
    elif score >= 75:
        assurance_level = "Good"
    elif score >= 60:
        assurance_level = "Needs Attention"
    elif score >= 40:
        assurance_level = "High Risk"
    else:
        assurance_level = "Critical"

    hierarchy_reason = (
        f"CA hierarchy detected: {hierarchy.get('independent_hierarchies', 0)} PKI chain(s), "
        f"{hierarchy.get('unclassified_count', 0)} unclassified CA(s)."
    )
    key_unknown = sum(
        1 for r in meaningful
        if r["category"] == "Key Protection" and r["original_status"] in {"Not Assessed", "Unknown Provider"}
    )
    key_reason = f"Key protection unknown for {key_unknown} CA(s)." if key_unknown else "Key protection evidence is available where collected."
    why = open_reasons[:3] or [
        "No confirmed Critical or High risk currently drives the PKI status."
    ]
    why.extend(accepted_reasons[:2])
    if coverage_gaps:
        why.append(
            f"{len(coverage_gaps)} assessment item(s) need additional evidence. "
            "These are coverage gaps and are not counted as confirmed risks."
        )
    why.extend([key_reason, hierarchy_reason])
    return {
        "score": score,
        "assurance_level": assurance_level,
        "coverage_score": coverage_score,
        "coverage_level": coverage_level,
        "open_risk_count": sum(open_counts.values()),
        "accepted_risk_count": sum(accepted_counts.values()),
        "open_critical": open_counts.get("Critical", 0),
        "open_high": open_counts.get("High", 0),
        "accepted_critical": accepted_counts.get("Critical", 0),
        "accepted_high": accepted_counts.get("High", 0),
        "why": why[:12],
        "open_reasons": open_reasons[:10],
        "accepted_reasons": accepted_reasons[:10],
        "coverage_gaps": coverage_gaps[:10],
    }


def _ca_records(cas: Iterable[CertificateAuthority], hierarchy: dict[str, Any], acceptances: dict[str, RiskAcceptance]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    subjects = {}
    for ca in cas:
        cert = ca_certificate(ca.config_json or {})
        if cert.get("subject"):
            subjects[str(cert["subject"])] = ca.name
    for ca in cas:
        config = ca.config_json or {}
        cert = ca_certificate(config)
        role = ca_role(ca)
        kp = key_protection(config)
        issuer = cert.get("issuer") or ""
        parent = subjects.get(str(issuer), "") if issuer and issuer != cert.get("subject") else ""
        role_status = "Pass" if role in {"root", "issuing"} else "Not Assessed"
        role_title = "Root CA Detected" if role == "root" else "Issuing CA Detected" if role == "issuing" else "CA role could not be classified"
        records.append(_record(
            object_type="ca",
            object_name=ca.name,
            category="PKI Architecture",
            title=role_title,
            status=role_status,
            severity="Medium" if role_status == "Not Assessed" else "Low",
            confidence="high" if role_status == "Pass" else "low",
            source="CA certificate subject/issuer",
            evidence={"subject": cert.get("subject"), "issuer": issuer, "parent_ca": parent or "External or not collected", "role": role},
            recommendation="Collect CA certificate Subject/Issuer evidence to classify hierarchy." if role_status == "Not Assessed" else "Maintain clear CA hierarchy documentation.",
            acceptances=acceptances,
            related_ca=ca.name,
        ))
        if kp["status"] == "HSM Protected":
            kp_status = "Pass"
            severity = "Low"
        elif kp["status"] == "Software Key":
            kp_status = "High Risk" if role == "root" else "Needs Attention"
            severity = "High" if role == "root" else "Medium"
        elif kp["status"] == "Unknown Provider":
            kp_status = "Needs Attention"
            severity = "Medium"
        else:
            kp_status = "Not Assessed"
            severity = "Medium"
        records.append(_record(
            object_type="ca",
            object_name=ca.name,
            category="Key Protection",
            title="CA key protection status",
            status=kp_status,
            severity=severity,
            confidence="high" if kp_status != "Not Assessed" else "low",
            source="collector key_protection.provider/storage",
            evidence=kp,
            recommendation="Use HSM/external KMS for high-value CA keys or document compensating controls.",
            acceptances=acceptances,
            related_ca=ca.name,
        ))
        audit = config.get("auditing_enabled")
        audit_status = "Pass" if audit is True else "Needs Attention" if audit is False else "Not Assessed"
        records.append(_record(
            object_type="ca",
            object_name=ca.name,
            category="Coverage Gaps",
            title="CA auditing evidence",
            status=audit_status,
            severity="Medium",
            confidence="medium" if audit is not None else "low",
            source="certutil CA\\AuditFilter" if audit is not None else "collector coverage",
            evidence=config.get("audit") if isinstance(config.get("audit"), dict) else {"auditing_enabled": audit},
            recommendation="Collect and review CA AuditFilter; enable CA auditing for issuance and configuration changes.",
            acceptances=acceptances,
            related_ca=ca.name,
        ))
    return records


def _health_records(health: dict[str, Any], acceptances: dict[str, RiskAcceptance]) -> list[dict[str, Any]]:
    records = []
    for item in health.get("items", []):
        status = item.get("status", "Not Assessed")
        severity = "Critical" if status == "Critical" else "Medium" if status in {"Warning", "Needs Attention", "Not Assessed"} else "Low"
        records.append(_record(
            object_type="health_check",
            object_name=item.get("affected_object", "PKI"),
            category="CA Health" if item.get("category") in {"CA Service Health", "CA Certificate Health", "CRL Health", "AIA Health", "OCSP Health"} else "Coverage Gaps",
            title=item.get("title", item.get("category", "Health check")),
            status="Needs Attention" if status == "Warning" else status,
            severity=severity,
            confidence="medium" if status != "Not Assessed" else "low",
            source=item.get("evidence", {}).get("collection_source", "PKI health assessment"),
            evidence=item.get("evidence", {}),
            recommendation=item.get("recommendation", "Review PKI health evidence."),
            acceptances=acceptances,
            related_ca=item.get("affected_object", ""),
        ))
    return records


def _best_practice_records(best_practices: dict[str, Any], acceptances: dict[str, RiskAcceptance]) -> list[dict[str, Any]]:
    records = []
    duplicate_ca_registry_titles = {
        "CA auditing should be enabled",
        "Root CA key protection should be known and appropriate",
        "Issuing CA key protection should be known and appropriate",
        "Unclassified CA key protection should be known and appropriate",
    }

    for item in best_practices.get("items", []):
        # These controls already have canonical CA registry records:
        # - CA auditing evidence
        # - CA key protection status
        # Keep the detailed checks on the Best Practices page, but do
        # not duplicate them in Posture, Evidence Gaps, or Reports.
        if item.get("title") in duplicate_ca_registry_titles:
            continue

        status = item.get("status", "Not Assessed")
        normalized = item.get("display_status") or ({"Fail": "High Risk", "Warning": "Needs Attention"}.get(status, status))
        records.append(_record(
            object_type="best_practice",
            object_name=item.get("affected_object", "PKI"),
            category="Best Practices" if item.get("category") not in {"Key Protection", "PKI Architecture"} else item.get("category"),
            title=item.get("title", "Best practice"),
            status=normalized,
            severity=item.get("severity", _severity_from_status(normalized)),
            confidence=item.get("confidence", "medium"),
            source=item.get("data_source", "collector"),
            evidence=item.get("evidence", {}),
            recommendation=item.get("recommendation", "Review best-practice evidence."),
            acceptances=acceptances,
            related_ca=item.get("affected_object", ""),
        ))
    return records


def _finding_records(findings: Iterable[Finding], acceptances: dict[str, RiskAcceptance]) -> list[dict[str, Any]]:
    records = []
    for finding in findings:
        if finding.coverage_state != "detected":
            continue
        records.append(_record(
            object_type="finding",
            object_name=finding.affected_object,
            category="Template Risk",
            title=finding.title,
            status=finding.severity,
            severity=finding.severity,
            confidence=finding.confidence,
            source="ADCS vulnerability assessment",
            evidence=finding.evidence_json or {},
            recommendation=finding.remediation,
            acceptances=acceptances,
            fingerprint=finding_fingerprint(finding),
            related_template=finding.affected_object,
            related_finding=finding.id,
        ))
    return records


def build_assessment_registry(
    cas: list[CertificateAuthority],
    templates: list[CertificateTemplate],
    certificates: list[IssuedCertificate],
    findings: list[Finding],
    health: dict[str, Any],
    best_practices: dict[str, Any],
    acceptances: dict[str, RiskAcceptance] | None = None,
) -> dict[str, Any]:
    acceptances = acceptances or {}
    hierarchy = build_pki_hierarchy(cas, health, best_practices)
    records = []
    records.extend(_ca_records(cas, hierarchy, acceptances))
    records.extend(_health_records(health, acceptances))
    records.extend(_best_practice_records(best_practices, acceptances))
    records.extend(_finding_records(findings, acceptances))
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record["object_type"]].append(record)
    assurance = _assurance(records, hierarchy)

    confirmed_risks = [
        record
        for record in records
        if not record["accepted_risk"] and _is_confirmed_risk(record)
    ]
    confirmed_risks = sorted(
        confirmed_risks,
        key=lambda record: (
            0 if record["severity"] == "Critical" else 1,
            record["category"],
            record["object_name"],
        ),
    )

    accepted_risks = [
        record
        for record in records
        if record["accepted_risk"] and _is_confirmed_risk(record)
    ]

    coverage_gaps = [
        record
        for record in records
        if _is_coverage_gap(record)
    ]

    potential_risks = [
        record
        for record in records
        if (
            not record["accepted_risk"]
            and record["original_status"] in {"Present / Not Tested"}
        )
    ]

    return {
        "records": records,
        "by_object_type": dict(grouped),
        "assurance": assurance,
        "hierarchy_summary": {
            "chains": hierarchy.get("independent_hierarchies", 0),
            "roots": hierarchy.get("root_count", 0),
            "issuing": hierarchy.get("issuing_count", 0),
            "unclassified": hierarchy.get("unclassified_count", 0),
        },
        "confirmed_risks": confirmed_risks,
        "open_risks": confirmed_risks,
        "confirmed_risk_count": len(confirmed_risks),
        "accepted_risks": accepted_risks,
        "coverage_gaps": coverage_gaps,
        "coverage_gap_count": len(coverage_gaps),
        "potential_risks": potential_risks,
    }
