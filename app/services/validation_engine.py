from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.entities import AuditLog, Finding, ValidationRun, ValidationStep
from app.services.validation_recipes import get_recipe_for_finding, recipe_hash

EVIDENCE_REPLAY_MODE = "evidence_replay"
RESULT_LABELS = {
    "exposure_indicated": "Exposure Indicated",
    "evidence_incomplete": "Evidence Incomplete",
    "no_exposure_indicated": "No Exposure Indicated",
    "replay_failed": "Replay Failed",
}
SAFETY_METADATA = {
    "mode": EVIDENCE_REPLAY_MODE,
    "live_commands_executed": False,
    "environment_changes": False,
    "certificate_requested": False,
    "authentication_attempted": False,
    "configuration_changed": False,
    "arbitrary_command_execution": False,
}
SECRET_MARKERS = ("password", "secret", "token", "credential", "private_key")


def result_label(result: str | None) -> str:
    return RESULT_LABELS.get(result or "", "Evidence Incomplete")


def sanitize_replay_value(value, depth: int = 0):
    if depth > 4:
        return "[nested evidence omitted]"
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            key_text = str(key)
            if any(marker in key_text.lower() for marker in SECRET_MARKERS):
                sanitized[key_text] = "[redacted]"
            else:
                sanitized[key_text] = sanitize_replay_value(item, depth + 1)
        return sanitized
    if isinstance(value, list):
        return [sanitize_replay_value(item, depth + 1) for item in value[:25]]
    if isinstance(value, tuple):
        return [sanitize_replay_value(item, depth + 1) for item in value[:25]]
    if value is None or isinstance(value, bool | int | float):
        return value
    text = str(value).replace("\x00", "").strip()
    return text[:500]


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [value]


def _meaningful(value) -> bool:
    if value in (None, "", [], {}, ()):
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


def calculate_replay_result(finding: Finding) -> tuple[str, str, str]:
    simulation = finding.simulation_json or {}
    preconditions = [item for item in _as_list(simulation.get("preconditions_met")) if _meaningful(item)]
    missing = [item for item in _as_list(simulation.get("missing_or_unconfirmed")) if _meaningful(item)]
    coverage_state = (finding.coverage_state or "").lower()

    if coverage_state in {"not_detected", "absent", "not_applicable"}:
        return (
            "no_exposure_indicated",
            "medium",
            "Stored evidence explicitly indicates the required trigger conditions are absent.",
        )
    if coverage_state not in {"detected", "assessed", "confirmed"}:
        return (
            "evidence_incomplete",
            "low",
            "Evidence coverage is incomplete, so CertShield cannot replay the exposure path reliably.",
        )
    if missing:
        return (
            "evidence_incomplete",
            "medium",
            "Important replay conditions are missing or unconfirmed in the collected evidence.",
        )
    if not preconditions:
        return (
            "evidence_incomplete",
            "low",
            "No meaningful preconditions were stored for this Finding, so replay cannot indicate exposure.",
        )
    return (
        "exposure_indicated",
        sanitize_replay_value(simulation.get("confidence") or finding.confidence or "medium"),
        "Collected evidence indicates that the exposure path may be usable. This is not live confirmation.",
    )


def build_replay_steps(finding: Finding) -> list[dict]:
    simulation = finding.simulation_json or {}
    evidence = finding.evidence_json or {}
    result, _, summary = calculate_replay_result(finding)
    steps: list[dict] = []

    def add(name: str, status: str, message: str, step_evidence: dict | None = None) -> None:
        steps.append(
            {
                "sequence": len(steps) + 1,
                "step_name": name,
                "status": status,
                "message": sanitize_replay_value(message),
                "evidence_json": sanitize_replay_value(step_evidence or {}),
            }
        )

    add(
        "Load collected finding evidence",
        "passed" if evidence or finding.simulation_summary else "missing",
        finding.simulation_summary or "Finding evidence was loaded from CertShield storage.",
        {
            "finding_id": finding.id,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "coverage_state": finding.coverage_state,
        },
    )
    path = simulation.get("path") or finding.esc_category or finding.title
    add(
        "Identify the simulated exposure path",
        "info" if path else "missing",
        f"Exposure path: {path}" if path else "No exposure path was stored for this Finding.",
        {"path": path},
    )
    for item in _as_list(simulation.get("preconditions_met")):
        if _meaningful(item):
            add(str(item), "exposed", f"Stored evidence indicates: {item}", {"precondition": item})
    for item in _as_list(simulation.get("missing_or_unconfirmed")):
        if _meaningful(item):
            add(str(item), "missing", f"Material condition is missing or unconfirmed: {item}", {"condition": item})
    blast_radius = simulation.get("blast_radius")
    add(
        "Evaluate likely blast radius",
        "info" if _meaningful(blast_radius) else "skipped",
        str(blast_radius) if _meaningful(blast_radius) else "No blast-radius evidence was stored for this Finding.",
        {"blast_radius": blast_radius},
    )
    actions = _as_list(simulation.get("actions_performed"))
    add(
        "Apply safety boundary",
        "skipped",
        "Mode: Evidence Replay. Live commands executed: No. Environment changes: None. This is not live validation.",
        {"actions_performed": actions, **SAFETY_METADATA},
    )
    add("Calculate final replay result", "info", result_label(result), {"result": result, "summary": summary})
    return steps


def _audit_details(run: ValidationRun, requested_by: str, final_result: str | None = None) -> dict:
    return {
        "validation_run_id": run.id,
        "finding_id": run.finding_id,
        "scan_id": run.scan_id,
        "recipe_id": run.recipe_id,
        "recipe_version": run.recipe_version,
        "correlation_id": run.correlation_id,
        "requested_user": requested_by,
        "final_result": final_result or run.result,
    }


def create_evidence_replay(db: Session, finding: Finding, requested_by: str) -> ValidationRun:
    recipe = get_recipe_for_finding(finding)
    now = datetime.utcnow()
    run = ValidationRun(
        finding_id=finding.id,
        scan_id=finding.scan_id,
        mode=EVIDENCE_REPLAY_MODE,
        recipe_id=recipe.recipe_id,
        recipe_version=recipe.version,
        recipe_hash=recipe_hash(recipe),
        target=finding.affected_object,
        status="queued",
        result="evidence_incomplete",
        confidence="low",
        summary="Evidence replay queued.",
        requested_by=requested_by,
        created_at=now,
        correlation_id=uuid4().hex,
        safety_json=dict(SAFETY_METADATA),
        evidence_json=sanitize_replay_value(
            {
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "coverage_state": finding.coverage_state,
                "simulation_summary": finding.simulation_summary,
                "simulation_json": finding.simulation_json or {},
                "evidence_json": finding.evidence_json or {},
            }
        ),
    )
    db.add(run)
    db.flush()
    db.add(AuditLog(actor=requested_by, action="validation_replay_requested", details_json=_audit_details(run, requested_by)))
    try:
        started = datetime.utcnow()
        run.status = "running"
        run.started_at = started
        db.add(AuditLog(actor=requested_by, action="validation_replay_started", details_json=_audit_details(run, requested_by)))
        result, confidence, summary = calculate_replay_result(finding)
        steps = build_replay_steps(finding)
        for step in steps:
            db.add(
                ValidationStep(
                    validation_run_id=run.id,
                    sequence=step["sequence"],
                    step_name=step["step_name"],
                    status=step["status"],
                    message=step["message"],
                    started_at=started,
                    completed_at=datetime.utcnow(),
                    evidence_json=step["evidence_json"],
                )
            )
        run.status = "completed"
        run.result = result
        run.confidence = confidence
        run.summary = summary
        run.completed_at = datetime.utcnow()
        db.add(AuditLog(actor=requested_by, action="validation_replay_completed", details_json=_audit_details(run, requested_by, result)))
        db.commit()
        db.refresh(run)
        return run
    except Exception:
        run.status = "failed"
        run.result = "replay_failed"
        run.confidence = "low"
        run.summary = "Evidence replay failed during internal processing. No live validation was performed."
        run.completed_at = datetime.utcnow()
        db.add(AuditLog(actor=requested_by, action="validation_replay_failed", details_json=_audit_details(run, requested_by, run.result)))
        db.commit()
        db.refresh(run)
        return run


def get_validation_history(db: Session, finding_id: int, limit: int = 10) -> list[ValidationRun]:
    return (
        db.query(ValidationRun)
        .filter_by(finding_id=finding_id)
        .order_by(ValidationRun.created_at.desc(), ValidationRun.id.desc())
        .limit(limit)
        .all()
    )


def serialize_validation_run(run: ValidationRun) -> dict:
    return {
        "id": run.id,
        "finding_id": run.finding_id,
        "finding_url": f"/findings/{run.finding_id}/simulate",
        "scan_id": run.scan_id,
        "mode": run.mode,
        "recipe_id": run.recipe_id,
        "recipe_version": run.recipe_version,
        "recipe_hash": run.recipe_hash,
        "target": run.target,
        "status": run.status,
        "result": run.result,
        "result_label": result_label(run.result),
        "confidence": run.confidence,
        "summary": run.summary,
        "requested_by": run.requested_by,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "correlation_id": run.correlation_id,
        "safety": sanitize_replay_value(run.safety_json or {}),
        "evidence": sanitize_replay_value(run.evidence_json or {}),
        "steps": [
            {
                "id": step.id,
                "sequence": step.sequence,
                "step_name": step.step_name,
                "status": step.status,
                "message": step.message,
                "started_at": step.started_at.isoformat() if step.started_at else None,
                "completed_at": step.completed_at.isoformat() if step.completed_at else None,
                "evidence": sanitize_replay_value(step.evidence_json or {}),
            }
            for step in sorted(run.steps, key=lambda item: item.sequence)
        ],
    }
