from __future__ import annotations

import hashlib
from datetime import date, datetime
from typing import Iterable

from sqlalchemy.orm import Session

from app.models.entities import Finding, RiskAcceptance


def issue_fingerprint(category: str, object_type: str, object_name: str, evidence_key: str) -> str:
    normalized = "|".join(
        part.strip().lower()
        for part in (category, object_type, object_name, evidence_key)
        if str(part).strip()
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def finding_fingerprint(finding: Finding) -> str:
    evidence = finding.evidence_json or {}
    evidence_key = evidence.get("stable_key") or evidence.get("template") or finding.rule_id or finding.title
    return issue_fingerprint(finding.esc_category, "template", finding.affected_object, str(evidence_key))


def acceptance_is_active(acceptance: RiskAcceptance, today: date | None = None) -> bool:
    if acceptance.status != "active":
        return False
    if not acceptance.expiry_date:
        return True
    today = today or datetime.utcnow().date()
    try:
        return date.fromisoformat(acceptance.expiry_date) >= today
    except ValueError:
        return False


def active_acceptance_map(db: Session) -> dict[str, RiskAcceptance]:
    rows = db.query(RiskAcceptance).filter(RiskAcceptance.status == "active").all()
    return {row.fingerprint: row for row in rows if acceptance_is_active(row)}


def decorate_findings(findings: Iterable[Finding], acceptances: dict[str, RiskAcceptance]) -> list[Finding]:
    decorated = []
    for finding in findings:
        fingerprint = finding_fingerprint(finding)
        acceptance = acceptances.get(fingerprint)
        setattr(finding, "fingerprint", fingerprint)
        setattr(finding, "accepted_risk", acceptance is not None)
        setattr(finding, "acceptance", acceptance)
        decorated.append(finding)
    return decorated


def accepted_counts(findings: Iterable[Finding], acceptances: dict[str, RiskAcceptance]) -> dict[str, int]:
    counts = {
        "accepted_total": 0,
        "accepted_critical": 0,
        "accepted_high": 0,
        "open_critical": 0,
        "open_high": 0,
    }
    for finding in findings:
        accepted = acceptances.get(finding_fingerprint(finding)) is not None
        if accepted:
            counts["accepted_total"] += 1
            if finding.severity == "Critical":
                counts["accepted_critical"] += 1
            elif finding.severity == "High":
                counts["accepted_high"] += 1
        elif finding.severity == "Critical":
            counts["open_critical"] += 1
        elif finding.severity == "High":
            counts["open_high"] += 1
    return counts
