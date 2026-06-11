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
    # A finding acceptance must be specific to:
    # category + template + finding title.
    #
    # Do not use evidence["template"] as the evidence key because
    # multiple findings on the same template would then share one
    # fingerprint.
    evidence_key = finding.title or finding.rule_id

    return issue_fingerprint(
        finding.esc_category,
        "template",
        finding.affected_object,
        str(evidence_key),
    )


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


def active_acceptance_map(
    db: Session,
) -> dict[str, RiskAcceptance]:
    rows = (
        db.query(RiskAcceptance)
        .filter(RiskAcceptance.status == "active")
        .all()
    )

    result: dict[str, RiskAcceptance] = {}

    for row in rows:
        if not acceptance_is_active(row):
            continue

        # Preserve the stored fingerprint.
        result[row.fingerprint] = row

        # Compatibility alias for older template acceptances that
        # were saved using a template-wide fingerprint.
        if row.object_type == "template":
            canonical = issue_fingerprint(
                row.category,
                "template",
                row.object_name,
                row.risk_title,
            )
            result.setdefault(canonical, row)

    return result


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
