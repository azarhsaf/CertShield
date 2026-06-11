from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy.orm import Session

from app.models.entities import GovernanceEvidence

MANUAL_CONTROL_TITLES = {
    "Root CA should be offline",
    "Root CA should not be domain joined",
    "Issuing CA should not run on a domain controller",
    "CA backup and recovery should be documented",
    "Published certificate template ownership",
    "Collector should run on a schedule",
    "Offline root backup should be protected",
    "Certificates issued to privileged accounts should be reviewed",
}


def governance_control_key(
    category: str,
    object_name: str,
    title: str,
) -> str:
    normalized = "|".join(
        str(value).strip().lower()
        for value in (category, object_name, title)
        if str(value).strip()
    )
    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


def _serialize(row: GovernanceEvidence) -> dict[str, Any]:
    return {
        "control_key": row.control_key,
        "category": row.category,
        "object_name": row.object_name,
        "control_title": row.control_title,
        "state": row.state,
        "owner": row.owner,
        "details": row.details,
        "evidence_reference": row.evidence_reference,
        "last_reviewed": row.last_reviewed,
        "next_review": row.next_review,
        "updated_by": row.updated_by,
        "updated_at": (
            row.updated_at.isoformat()
            if row.updated_at
            else None
        ),
    }


def governance_evidence_map(
    db: Session,
) -> dict[str, dict[str, Any]]:
    rows = db.query(GovernanceEvidence).all()
    return {
        row.control_key: _serialize(row)
        for row in rows
    }


def apply_governance_evidence(
    items: list[dict],
    evidence_map: dict[str, dict[str, Any]],
) -> list[dict]:
    output: list[dict] = []

    for original in items:
        item = dict(original)

        key = governance_control_key(
            item.get("category", ""),
            item.get("affected_object", ""),
            item.get("title", ""),
        )

        item["control_key"] = key
        item["manual_control"] = (
            item.get("title") in MANUAL_CONTROL_TITLES
            or item.get("data_source")
            in {"operator evidence", "deployment"}
        )

        operator_evidence = evidence_map.get(key)
        item["governance_evidence"] = (
            operator_evidence or {}
        )

        if operator_evidence:
            state = operator_evidence.get("state")

            if state == "implemented":
                status = "Pass"
            elif state == "partial":
                status = "Warning"
            elif state == "not_implemented":
                status = (
                    "Fail"
                    if item.get("severity")
                    in {"Critical", "High"}
                    else "Warning"
                )
            else:
                status = item.get(
                    "status",
                    "Not Assessed",
                )

            item["status"] = status
            item["display_status"] = {
                "Fail": "High Risk",
                "Warning": "Needs Attention",
            }.get(status, status)

            item["data_source"] = "operator evidence"
            item["not_assessed_reason"] = None
            item["confidence"] = (
                "high"
                if state == "implemented"
                else "medium"
            )

            evidence = dict(item.get("evidence") or {})
            evidence["operator_evidence"] = (
                operator_evidence
            )
            item["evidence"] = evidence

        output.append(item)

    return output
