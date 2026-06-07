from __future__ import annotations

from collections import Counter
from typing import Any

from app.models.entities import Finding

SEVERITY_WEIGHT = {"Critical": 25, "High": 12, "Medium": 6, "Low": 2}


def _score_status(score: int | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 90:
        return "Strong"
    if score >= 70:
        return "Acceptable"
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


def assess_pki_posture(findings: list[Finding], health: dict[str, Any], best_practices: dict[str, Any], coverage: dict[str, str], scan_summary: dict[str, Any]) -> dict:
    severity_counts = Counter(f.severity for f in findings if f.coverage_state == "detected")
    not_assessed = sum(1 for state in coverage.values() if state in {"not_assessed", "insufficient_data"})
    health_score = health.get("score")
    best_score = best_practices.get("score")
    coverage_quality = _coverage_quality(coverage)

    if health_score is None and best_score is None and not findings:
        score = None
    else:
        score = 100
        score -= severity_counts.get("Critical", 0) * 18
        score -= severity_counts.get("High", 0) * 9
        score -= severity_counts.get("Medium", 0) * 4
        if isinstance(health_score, int):
            score -= max(0, 100 - health_score) // 3
        else:
            score -= 8
        if isinstance(best_score, int):
            score -= max(0, 100 - best_score) // 4
        else:
            score -= 8
        score -= not_assessed * 3
        score -= max(0, 100 - coverage_quality) // 5
        score = max(0, min(100, score))

    top_risks = [_risk_from_finding(f) for f in findings if f.coverage_state == "detected"]
    top_risks.extend(
        {
            "source": "PKI Health",
            "title": item["title"],
            "severity": "Critical" if item["status"] == "Critical" else "High",
            "category": item["category"],
            "affected_object": item["affected_object"],
            "risk_score": 90 if item["status"] == "Critical" else 65,
            "coverage_state": "detected",
            "recommendation": item["recommendation"],
        }
        for item in health.get("items", [])
        if item.get("status") in {"Critical", "Warning"}
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
        if item.get("status") in {"Fail", "Warning"}
    )
    top_risks = sorted(top_risks, key=lambda r: r["risk_score"], reverse=True)[:10]

    remediation_priorities = {
        "priority_1": [risk for risk in top_risks if risk["severity"] == "Critical" or risk["risk_score"] >= 85][:6],
        "priority_2": [risk for risk in top_risks if risk["severity"] == "High" or 60 <= risk["risk_score"] < 85][:8],
        "priority_3": [risk for risk in top_risks if risk["risk_score"] < 60][:8],
    }

    missing = "Not Assessed - Collector did not provide this data."
    crl_collected = any(
        "CRL" in item.get("category", "") and item.get("status") != "Not Assessed"
        for item in health.get("items", [])
    )
    aia_collected = any(
        "AIA" in item.get("category", "") and item.get("status") != "Not Assessed"
        for item in health.get("items", [])
    )
    ocsp_collected = any(
        "OCSP" in item.get("category", "") and item.get("status") != "Not Assessed"
        for item in health.get("items", [])
    )
    backup_collected = any(
        item.get("category") == "Backup and Recovery" and item.get("status") != "Not Assessed"
        for item in best_practices.get("items", [])
    )
    data_coverage = {
        "CAs collected": "Collected" if scan_summary.get("cas", 0) else missing,
        "Templates collected": "Collected" if scan_summary.get("templates", 0) else missing,
        "Template ACLs collected": "Collected" if coverage.get("ESC4-like") in {"detected", "not_detected"} else missing,
        "Issued certificates collected": "Collected" if scan_summary.get("certificates", 0) else missing,
        "CA registry/config collected": "Collected" if coverage.get("ESC6-like") in {"detected", "not_detected"} else missing,
        "CRL data collected": "Collected" if crl_collected else missing,
        "AIA data collected": "Collected" if aia_collected else missing,
        "OCSP data collected": "Collected" if ocsp_collected else missing,
        "Backup evidence collected": "Collected" if backup_collected else missing,
        "Root CA details collected": "Collected" if any(item.get("category") == "Root CA" for item in best_practices.get("items", [])) else missing,
        "Issuing CA details collected": "Collected" if any(item.get("category") == "Issuing CA" for item in best_practices.get("items", [])) else missing,
    }

    return {
        "product_label": "CertShield PKI Posture Management",
        "build": "Phase 1 Posture",
        "score": score,
        "status": _score_status(score),
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
