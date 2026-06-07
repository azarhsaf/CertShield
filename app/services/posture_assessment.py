from __future__ import annotations

from collections import Counter
from typing import Any

from app.models.entities import Finding

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


def _risk_from_finding(finding: Finding) -> dict:
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
    }


def _health_not_assessed(health: dict[str, Any], category: str) -> bool:
    return any(
        item.get("category") == category and item.get("status") == "Not Assessed"
        for item in health.get("items", [])
    )


def _finding_contains(findings: list[Finding], text: str) -> bool:
    needle = text.lower()
    for finding in findings:
        if finding.coverage_state != "detected":
            continue
        haystack = f"{finding.title} {finding.trigger_conditions} {finding.rationale}".lower()
        if needle in haystack:
            return True
    return False


def assess_pki_posture(
    findings: list[Finding],
    health: dict[str, Any],
    best_practices: dict[str, Any],
    coverage: dict[str, str],
    scan_summary: dict[str, Any],
) -> dict:
    detected = [f for f in findings if f.coverage_state == "detected"]
    severity_counts = Counter(f.severity for f in detected)
    not_assessed = sum(1 for state in coverage.values() if state in {"not_assessed", "insufficient_data"})
    not_assessed_ratio = not_assessed / len(coverage) if coverage else 1
    health_score = health.get("score")
    best_score = best_practices.get("score")
    coverage_quality = _coverage_quality(coverage)
    explanations: list[str] = []

    if health_score is None and best_score is None and not findings:
        score = None
    else:
        score = 100
        critical_penalty = min(60, severity_counts.get("Critical", 0) * 15)
        high_penalty = min(40, severity_counts.get("High", 0) * 8)
        score -= critical_penalty + high_penalty
        if critical_penalty:
            explanations.append(f"-{critical_penalty}: Critical ADCS findings detected.")
        if high_penalty:
            explanations.append(f"-{high_penalty}: High ADCS findings detected.")

        if isinstance(health_score, int) and health_score < 70:
            score -= 20
            explanations.append("-20: PKI Health score is below 70.")
        elif health_score is None:
            score -= 15
            explanations.append("-15: PKI Health score is unknown.")

        if isinstance(best_score, int) and best_score < 70:
            score -= 20
            explanations.append("-20: Best Practice score is below 70.")
        elif best_score is None:
            score -= 15
            explanations.append("-15: Best Practice score is unknown.")

        if _health_not_assessed(health, "CRL Health"):
            score -= 10
            explanations.append("-10: CRL health is Not Assessed.")
        if _health_not_assessed(health, "CA Certificate Health"):
            score -= 10
            explanations.append("-10: CA certificate expiry is Not Assessed.")
        if coverage_quality < 60:
            score -= 20
            explanations.append("-20: Collector coverage is below 60%.")
        if not_assessed_ratio > 0.4:
            score -= 20
            explanations.append("-20: More than 40% of posture checks are Not Assessed or Insufficient Data.")
        if _finding_contains(findings, "broad enrollment"):
            score -= 15
            explanations.append("-15: Broad enrollment on authentication-relevant templates detected.")
        if _finding_contains(findings, "requester-controlled") or _finding_contains(findings, "enrollee-supplied"):
            score -= 15
            explanations.append("-15: Requester-controlled subject/SAN exposure detected.")
        if not scan_summary.get("certificates", 0):
            score -= 5
            explanations.append("-5: Issued certificate inventory was not collected.")

        if severity_counts.get("Critical", 0):
            score = min(score, 69)
            explanations.append("Score capped at 69 because critical ADCS findings were detected.")
        if severity_counts.get("Critical", 0) > 1:
            score = min(score, 49)
            explanations.append("Score capped at 49 because multiple critical ADCS findings were detected.")
        if health.get("limited_visibility") or not_assessed_ratio > 0.5:
            score = min(score, 69)
            explanations.append("Score capped at 69 because visibility is limited by Not Assessed checks.")
        score = max(0, min(100, score))

    top_risks = [_risk_from_finding(f) for f in detected]
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
        }
        for item in best_practices.get("items", [])
        if item.get("status") in {"Fail", "Warning", "Not Assessed"}
    )
    top_risks = sorted(top_risks, key=lambda r: r["risk_score"], reverse=True)[:10]

    remediation_priorities = {
        "priority_1": [risk for risk in top_risks if risk["severity"] == "Critical" or risk["risk_score"] >= 85][:6],
        "priority_2": [risk for risk in top_risks if risk["severity"] == "High" or 60 <= risk["risk_score"] < 85][:8],
        "priority_3": [risk for risk in top_risks if risk["risk_score"] < 60][:8],
    }

    missing = "Not Assessed - Collector did not provide this data."
    health_coverage = scan_summary.get("health_coverage", {}) or {}
    data_coverage = {
        "CAs collected": "Collected" if scan_summary.get("cas", 0) else missing,
        "Templates collected": "Collected" if scan_summary.get("templates", 0) else missing,
        "Template ACLs collected": "Collected" if health_coverage.get("template_acl_collected") else missing,
        "Issued certificates collected": "Collected" if scan_summary.get("certificates", 0) else missing,
        "CA registry/config collected": "Collected" if health_coverage.get("ca_registry_collected") else missing,
        "CRL data collected": "Collected" if health_coverage.get("crl_collected") else missing,
        "AIA data collected": "Collected" if health_coverage.get("aia_collected") else missing,
        "OCSP data collected": "Collected" if health_coverage.get("ocsp_collected") else missing,
        "Backup evidence collected": "Collected" if any(
            item.get("category") == "Backup and Recovery" and item.get("status") != "Not Assessed"
            for item in best_practices.get("items", [])
        ) else missing,
        "Root CA details collected": "Collected" if any(
            item.get("category") == "Root CA" for item in best_practices.get("items", [])
        ) else missing,
        "Issuing CA details collected": "Collected" if any(
            item.get("category") == "Issuing CA" for item in best_practices.get("items", [])
        ) else missing,
    }

    limited_visibility = bool(score is not None and (health.get("limited_visibility") or not_assessed_ratio > 0.5))
    return {
        "product_label": "CertShield PKI Posture Management",
        "build": "Phase 1 Posture",
        "score": score,
        "status": _score_status(score, limited_visibility),
        "limited_visibility": limited_visibility,
        "score_explanation": explanations,
        "summary": {
            "pki_health_score": health_score,
            "best_practice_score": best_score,
            "critical_findings": severity_counts.get("Critical", 0),
            "high_findings": severity_counts.get("High", 0),
            "not_assessed_checks": not_assessed,
            "collector_coverage": coverage_quality,
        },
        "top_risks": top_risks,
        "remediation_priorities": remediation_priorities,
        "data_coverage": data_coverage,
    }
