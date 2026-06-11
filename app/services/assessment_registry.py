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
    "CA Health": 30,
    "Template Risk": 25,
    "Key Protection": 15,
    "Best Practices": 15,
    "PKI Architecture": 10,
    "Coverage Gaps": 0,
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


def _assurance(
    records: list[dict[str, Any]],
    hierarchy: dict[str, Any],
) -> dict[str, Any]:
    meaningful = [
        record
        for record in records
        if record.get("object_type") != "pki_hierarchy"
    ]

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
            "accepted_critical": 0,
            "accepted_high": 0,
            "why": ["No meaningful evidence was collected yet."],
            "open_reasons": [],
            "accepted_reasons": [],
            "coverage_gaps": [
                "Run a collector scan to populate PKI evidence."
            ],
            "deduction_breakdown": [],
        }

    coverage_score, coverage_level, coverage_gaps = (
        _coverage_level(meaningful)
    )

    open_records = [
        record
        for record in meaningful
        if (
            not record.get("accepted_risk")
            and _is_confirmed_risk(record)
        )
    ]

    accepted_records = [
        record
        for record in meaningful
        if (
            record.get("accepted_risk")
            and _is_confirmed_risk(record)
        )
    ]

    def group_families(
        rows: list[dict[str, Any]],
    ) -> dict[tuple[str, str], list[dict[str, Any]]]:
        families: dict[
            tuple[str, str],
            list[dict[str, Any]],
        ] = defaultdict(list)

        for row in rows:
            key = (
                str(row.get("category") or "Other"),
                str(row.get("title") or "Risk"),
            )
            families[key].append(row)

        return families

    open_families = group_families(open_records)
    accepted_families = group_families(
        accepted_records
    )

    category_amounts = Counter()
    deduction_breakdown = []

    for (category, title), family in open_families.items():
        severity = (
            "Critical"
            if any(
                row.get("severity") == "Critical"
                for row in family
            )
            else "High"
        )

        affected_assets = {
            str(row.get("object_name") or "PKI")
            for row in family
        }

        affected_count = len(affected_assets)

        base = 15 if severity == "Critical" else 8
        spread_rate = 2 if severity == "Critical" else 1
        spread = min(
            max(affected_count - 1, 0),
            5,
        ) * spread_rate

        deduction = base + spread
        category_amounts[category] += deduction

        deduction_breakdown.append(
            {
                "category": category,
                "title": title,
                "severity": severity,
                "affected_assets": affected_count,
                "raw_deduction": deduction,
                "accepted": False,
            }
        )

    # Accepted risk remains visible as residual governance exposure,
    # but must always deduct less than the corresponding open risk.
    for (category, title), family in accepted_families.items():
        severity = (
            "Critical"
            if any(
                row.get("severity") == "Critical"
                for row in family
            )
            else "High"
        )

        deduction = 2 if severity == "Critical" else 1
        category_amounts[category] += deduction

        deduction_breakdown.append(
            {
                "category": category,
                "title": title,
                "severity": severity,
                "affected_assets": len(
                    {
                        str(
                            row.get("object_name")
                            or "PKI"
                        )
                        for row in family
                    }
                ),
                "raw_deduction": deduction,
                "accepted": True,
            }
        )

    capped_deductions = {}

    for category, amount in category_amounts.items():
        cap = CATEGORY_CAPS.get(category, 15)
        capped_deductions[category] = min(
            cap,
            amount,
        )

    total_deduction = sum(
        capped_deductions.values()
    )

    score = max(
        0,
        min(100, 100 - total_deduction),
    )

    if coverage_score == 0:
        score = None
        assurance_level = "Unknown / Not Enough Data"
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

    open_counts = Counter(
        row.get("severity")
        for row in open_records
    )
    accepted_counts = Counter(
        row.get("severity")
        for row in accepted_records
    )

    open_reasons = []

    for family in sorted(
        deduction_breakdown,
        key=lambda item: item["raw_deduction"],
        reverse=True,
    ):
        if family["accepted"]:
            continue

        open_reasons.append(
            f"{family['severity']} risk: "
            f"{family['title']} "
            f"({family['affected_assets']} affected asset(s))."
        )

    accepted_reasons = [
        (
            f"{family['severity']} accepted by policy: "
            f"{family['title']}."
        )
        for family in deduction_breakdown
        if family["accepted"]
    ]

    key_unknown = sum(
        1
        for record in meaningful
        if (
            record.get("category") == "Key Protection"
            and record.get("original_status")
            in {"Not Assessed", "Unknown Provider"}
        )
    )

    hierarchy_reason = (
        "CA hierarchy detected: "
        f"{hierarchy.get('independent_hierarchies', 0)} "
        "PKI chain(s), "
        f"{hierarchy.get('unclassified_count', 0)} "
        "unclassified CA(s)."
    )

    why = open_reasons[:3] or [
        "No confirmed Critical or High risk currently "
        "drives the PKI status."
    ]

    why.extend(accepted_reasons[:2])

    if coverage_gaps:
        why.append(
            "Additional assessment evidence is required. "
            "Evidence gaps do not reduce the assurance score."
        )

    why.append(
        (
            f"Key protection unknown for {key_unknown} CA(s)."
            if key_unknown
            else "Key protection evidence is available where collected."
        )
    )
    why.append(hierarchy_reason)

    return {
        "score": score,
        "assurance_level": assurance_level,
        "coverage_score": coverage_score,
        "coverage_level": coverage_level,
        "open_risk_count": len(open_records),
        "accepted_risk_count": len(accepted_records),
        "open_critical": open_counts.get("Critical", 0),
        "open_high": open_counts.get("High", 0),
        "accepted_critical": accepted_counts.get(
            "Critical",
            0,
        ),
        "accepted_high": accepted_counts.get("High", 0),
        "why": why[:12],
        "open_reasons": open_reasons[:10],
        "accepted_reasons": accepted_reasons[:10],
        "coverage_gaps": coverage_gaps[:10],
        "deduction_breakdown": deduction_breakdown,
        "category_deductions": capped_deductions,
        "score_basis": (
            "Unique confirmed Critical/High risk families "
            "with limited exposure scaling."
        ),
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


def _best_practice_records(
    best_practices: dict[str, Any],
    acceptances: dict[str, RiskAcceptance],
) -> list[dict[str, Any]]:
    records = []

    canonical_ca_titles = {
        "CA auditing should be enabled",
        "Root CA key protection should be known and appropriate",
        "Issuing CA key protection should be known and appropriate",
        "Unclassified CA key protection should be known and appropriate",
    }

    architecture_display_titles = {
        "CA role classified from certificate subject/issuer",
        "Root CA detected",
        "Root CA Detected",
        "Issuing CA detected",
        "Issuing CA Detected",
    }

    technical_template_titles = {
        "Avoid broad enrollment on authentication templates",
        "Avoid requester-supplied subject/SAN unless approved",
        "Avoid overly long validity periods",
    }

    for item in best_practices.get("items", []) or []:
        if not isinstance(item, dict):
            continue

        title = item.get("title", "Best practice")
        category = item.get("category", "Best Practices")

        # These already have canonical CA records.
        if title in canonical_ca_titles:
            continue

        # Architecture is displayed by PKI Hierarchy.
        if title in architecture_display_titles:
            continue

        # Template security findings are represented canonically
        # by Findings/Templates and must not be scored twice.
        if (
            category == "Templates"
            or title in technical_template_titles
        ):
            continue

        # Certificate expiry belongs to PKI Health.
        if title == "Certificate expiry should be monitored":
            continue

        status = item.get("status", "Not Assessed")
        normalized = (
            item.get("display_status")
            or {
                "Fail": "High Risk",
                "Warning": "Needs Attention",
            }.get(status, status)
        )

        object_name = item.get(
            "affected_object",
            "PKI",
        )

        records.append(
            _record(
                object_type="best_practice",
                object_name=object_name,
                category=(
                    category
                    if category
                    in {"Key Protection", "PKI Architecture"}
                    else "Best Practices"
                ),
                title=title,
                status=normalized,
                severity=item.get(
                    "severity",
                    _severity_from_status(normalized),
                ),
                confidence=item.get(
                    "confidence",
                    "medium",
                ),
                source=item.get(
                    "data_source",
                    "collector",
                ),
                evidence=item.get("evidence", {}),
                recommendation=item.get(
                    "recommendation",
                    "Review governance evidence.",
                ),
                acceptances=acceptances,
                related_ca=(
                    object_name
                    if category
                    in {
                        "Root CA",
                        "Issuing CA",
                        "Key Protection",
                        "Backup and Recovery",
                    }
                    else ""
                ),
            )
        )

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
    records.extend(
        _finding_records(findings, acceptances)
    )

    # Multiple assessment engines can observe the same condition.
    # Keep one canonical record per fingerprint and prefer the
    # strongest definitive result.
    status_rank = {
        "Critical": 100,
        "High Risk": 90,
        "Fail": 90,
        "Needs Attention": 70,
        "Warning": 70,
        "Present / Not Tested": 45,
        "Not Assessed": 30,
        "Unknown": 20,
        "Evidence Missing": 20,
        "Pass": 10,
        "Healthy": 10,
    }

    canonical_records: dict[str, dict[str, Any]] = {}

    for record in records:
        fingerprint = record.get("fingerprint")

        if not fingerprint:
            fingerprint = registry_fingerprint(
                record.get("category", ""),
                record.get("object_type", ""),
                record.get("object_name", ""),
                record.get("title", ""),
            )
            record["fingerprint"] = fingerprint

        current = canonical_records.get(fingerprint)

        if current is None:
            canonical_records[fingerprint] = record
            continue

        current_rank = status_rank.get(
            current.get("original_status"),
            0,
        )
        new_rank = status_rank.get(
            record.get("original_status"),
            0,
        )

        if new_rank > current_rank:
            canonical_records[fingerprint] = record

    records = list(canonical_records.values())
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
