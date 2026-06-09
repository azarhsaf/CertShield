from __future__ import annotations

from collections import Counter
from typing import Any

from app.models.entities import Finding
from app.services.risk_acceptance import finding_fingerprint

SEVERITY_WEIGHT = {"Critical": 25, "High": 12, "Medium": 6, "Low": 2}


def _score_status(score: int | None, limited_visibility: bool = False) -> str:
    if score is None:
        return "Unknown"
    if limited_visibility and score <= 69:
        return "Limited Visibility"
    if score >= 90:
        return "Strong"
    if score >= 70:
        return "Moderate"
    if score >= 40:
        return "Weak"
    return "Critical"


def _coverage_quality(coverage: dict[str, str]) -> int:
    if not coverage:
        return 0
    good = sum(1 for state in coverage.values() if state in {"detected", "not_detected"})
    return round(good * 100 / len(coverage))


def _risk_from_finding(finding: Finding, accepted: bool = False) -> dict:
    evidence = getattr(finding, "evidence_json", None) or getattr(finding, "evidence", None) or {}
    risk_score = evidence.get("risk_score") or SEVERITY_WEIGHT.get(finding.severity, 2) * 4
    return {
        "source": "ADCS Vulnerability Assessment",
        "title": finding.title,
        "severity": finding.severity,
        "category": finding.esc_category,
        "affected_object": finding.affected_object,
        "risk_score": min(int(risk_score), 100),
        "coverage_state": finding.coverage_state,
        "recommendation": finding.remediation,
        "accepted_risk": accepted,
    }


def _finding_contains(findings: list[Finding], text: str) -> bool:
    needle = text.lower()
    for finding in findings:
        if finding.coverage_state != "detected":
            continue
        haystack = f"{finding.title} {finding.trigger_conditions} {finding.rationale}".lower()
        if needle in haystack:
            return True
    return False


def _finding_score(findings: list[Finding]) -> int:
    counts = Counter(f.severity for f in findings if f.coverage_state == "detected")
    return max(
        0,
        100
        - min(70, counts.get("Critical", 0) * 25)
        - min(50, counts.get("High", 0) * 12)
        - min(30, counts.get("Medium", 0) * 5),
    )


def _template_governance_score(findings: list[Finding]) -> int:
    score = 100
    if _finding_contains(findings, "broad enrollment"):
        score -= 25
    if _finding_contains(findings, "requester-controlled") or _finding_contains(findings, "enrollee-supplied"):
        score -= 25
    score -= min(30, sum(1 for f in findings if f.severity in {"Critical", "High"}) * 5)
    return max(0, score)


def _key_score(best_practices: dict[str, Any]) -> int:
    key_items = [item for item in best_practices.get("items", []) if item.get("category") == "Key Protection"]
    if not key_items:
        return 60
    if any(item.get("status") == "Fail" for item in key_items):
        return 35
    if any(item.get("status") == "Warning" for item in key_items):
        return 60
    if all(item.get("status") == "Pass" for item in key_items):
        return 100
    return 65


def _weighted_score(
    findings: list[Finding],
    health: dict[str, Any],
    best_practices: dict[str, Any],
    coverage_quality: int,
) -> int:
    health_score = health.get("score") if isinstance(health.get("score"), int) else 50
    best_score = best_practices.get("score") if isinstance(best_practices.get("score"), int) else 50
    parts = {
        "ADCS/CA vulnerability findings": (_finding_score(findings), 30),
        "PKI health": (health_score, 20),
        "Best-practice gaps": (best_score, 20),
        "Template/profile governance risk": (_template_governance_score(findings), 15),
        "Key protection/HSM posture": (_key_score(best_practices), 10),
        "Coverage/confidence": (coverage_quality, 5),
    }
    return round(sum(score * weight for score, weight in parts.values()) / 100)


def assess_pki_posture(
    findings: list[Finding],
    health: dict[str, Any],
    best_practices: dict[str, Any],
    coverage: dict[str, str],
    scan_summary: dict[str, Any],
    accepted_fingerprints: set[str] | None = None,
) -> dict:
    accepted_fingerprints = accepted_fingerprints or set()
    detected = [f for f in findings if f.coverage_state == "detected"]
    open_findings = [f for f in detected if finding_fingerprint(f) not in accepted_fingerprints]
    accepted_findings = [f for f in detected if finding_fingerprint(f) in accepted_fingerprints]
    severity_counts = Counter(f.severity for f in open_findings)
    not_assessed = sum(1 for state in coverage.values() if state in {"not_assessed", "insufficient_data"})
    not_assessed_ratio = not_assessed / len(coverage) if coverage else 1
    coverage_quality = _coverage_quality(coverage)
    explanations: list[str] = []

    if health.get("score") is None and best_practices.get("score") is None and not findings:
        raw_score = adjusted_score = None
    else:
        raw_score = _weighted_score(detected, health, best_practices, coverage_quality)
        adjusted_score = _weighted_score(open_findings, health, best_practices, coverage_quality)
        explanations.append("Scores use a weighted model across findings, PKI health, best practices, template governance, key protection, and coverage.")
        if accepted_findings:
            explanations.append(f"{len(accepted_findings)} risk(s) are accepted by customer policy and still visible in reports.")
        if severity_counts.get("Critical", 0):
            adjusted_score = min(adjusted_score, 70)
            explanations.append("Adjusted score capped at 70 because critical ADCS findings remain open.")
        if severity_counts.get("Critical", 0) > 1:
            adjusted_score = min(adjusted_score, 55)
            explanations.append("Adjusted score capped at 55 because multiple critical ADCS findings remain open.")
        if _finding_contains(open_findings, "client authentication") and _finding_contains(open_findings, "broad enrollment"):
            adjusted_score = min(adjusted_score, 65)
            explanations.append("Adjusted score capped at 65 because dangerous authentication template exposure remains open.")
        if health.get("limited_visibility") or not_assessed_ratio > 0.5:
            adjusted_score = min(adjusted_score, 70)
            explanations.append("Adjusted score capped at 70 because assessment visibility is limited.")
        raw_score = max(0, min(100, raw_score))
        adjusted_score = max(0, min(100, adjusted_score))

    top_risks = [_risk_from_finding(f, False) for f in open_findings]
    top_risks.extend(_risk_from_finding(f, True) for f in accepted_findings)
    top_risks.extend(
        {
            "source": "PKI Health",
            "title": item["title"],
            "severity": "Critical" if item["status"] == "Critical" else "High",
            "category": item["category"],
            "affected_object": item["affected_object"],
            "risk_score": 90 if item["status"] == "Critical" else 65,
            "coverage_state": "detected" if item["status"] != "Not Assessed" else "not_assessed",
            "recommendation": item["recommendation"],
            "accepted_risk": False,
        }
        for item in health.get("items", [])
        if item.get("status") in {"Critical", "Warning", "Not Assessed"}
    )
    top_risks.extend(
        {
            "source": "Best Practice Gap",
            "title": item["title"],
            "severity": item["severity"],
            "category": item["category"],
            "affected_object": item["affected_object"],
            "risk_score": 75 if item["severity"] in {"Critical", "High"} else 45,
            "coverage_state": item["status"],
            "recommendation": item["recommendation"],
            "accepted_risk": False,
        }
        for item in best_practices.get("items", [])
        if item.get("status") in {"Fail", "Warning", "Not Assessed"}
    )
    top_risks = sorted(top_risks, key=lambda r: r["risk_score"], reverse=True)[:10]

    remediation_priorities = {
        "priority_1": [risk for risk in top_risks if not risk.get("accepted_risk") and (risk["severity"] == "Critical" or risk["risk_score"] >= 85)][:6],
        "priority_2": [risk for risk in top_risks if not risk.get("accepted_risk") and (risk["severity"] == "High" or 60 <= risk["risk_score"] < 85)][:8],
        "priority_3": [risk for risk in top_risks if not risk.get("accepted_risk") and risk["risk_score"] < 60][:8],
    }

    missing = "Not Assessed - Collector did not provide this data."
    health_coverage = scan_summary.get("health_coverage", {}) or {}
    data_coverage = {
        "CAs collected": "Collected" if scan_summary.get("cas", 0) else missing,
        "Templates collected": "Collected" if scan_summary.get("templates", 0) else missing,
        "Template ACLs collected": "Collected" if health_coverage.get("template_acl_collected") else missing,
        "Issued certificates collected": "Collected" if health_coverage.get("issued_certificates_collected") else missing,
        "CA registry/config collected": "Collected" if health_coverage.get("ca_registry_collected") else missing,
        "CRL data collected": "Collected" if health_coverage.get("crl_collected") else missing,
        "AIA data collected": "Collected" if health_coverage.get("aia_collected") else missing,
        "OCSP data collected": "Collected" if health_coverage.get("ocsp_collected") else missing,
        "Key protection collected": "Collected" if health_coverage.get("key_protection_collected") else missing,
    }

    limited_visibility = bool(adjusted_score is not None and (health.get("limited_visibility") or not_assessed_ratio > 0.5))
    return {
        "product_label": "CertShield PKI Posture Management",
        "build": "Phase 2",
        "score": adjusted_score,
        "raw_score": raw_score,
        "adjusted_score": adjusted_score,
        "accepted_risk_count": len(accepted_findings),
        "status": _score_status(adjusted_score, limited_visibility),
        "grade": _score_status(adjusted_score, limited_visibility),
        "confidence": health.get("confidence", "Low" if limited_visibility else "Medium"),
        "coverage": coverage_quality,
        "limited_visibility": limited_visibility,
        "score_explanation": explanations,
        "top_factors": [risk["title"] for risk in top_risks[:5]],
        "summary": {
            "pki_health_score": health.get("score"),
            "best_practice_score": best_practices.get("score"),
            "critical_findings": severity_counts.get("Critical", 0),
            "high_findings": severity_counts.get("High", 0),
            "accepted_critical": sum(1 for f in accepted_findings if f.severity == "Critical"),
            "accepted_high": sum(1 for f in accepted_findings if f.severity == "High"),
            "not_assessed_checks": not_assessed,
            "collector_coverage": coverage_quality,
        },
        "top_risks": top_risks,
        "accepted_risks": [_risk_from_finding(f, True) for f in accepted_findings],
        "remediation_priorities": remediation_priorities,
        "data_coverage": data_coverage,
    }
