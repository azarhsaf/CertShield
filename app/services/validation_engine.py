from __future__ import annotations

import re
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
SECRET_MARKERS = ("password", "secret", "token", "credential", "private key", "private_key", "ticket", "hash", "cookie", "authorization", "bearer")
WALKTHROUGH_INPUT_PATTERN = re.compile(r"[^A-Za-z0-9_.@-]+")


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


def sanitize_walkthrough_input(value: object) -> str:
    """Return a safe, non-secret walkthrough note value.

    Walkthrough values are labels only. They are never interpreted as commands,
    targets, credentials, or live validation parameters.
    """
    text = str(value or "").replace("\x00", "").strip()[:100]
    lowered = text.lower()
    if any(marker in lowered for marker in SECRET_MARKERS):
        return ""
    return WALKTHROUGH_INPUT_PATTERN.sub("", text)[:100]


def store_walkthrough_input(run: ValidationRun, name: str, value: object) -> tuple[str, bool]:
    safe_name = sanitize_walkthrough_input(name) or "walkthrough_note"
    sanitized = sanitize_walkthrough_input(value)
    evidence = dict(run.evidence_json or {})
    inputs = dict(evidence.get("walkthrough_inputs") or {})
    accepted = bool(sanitized)
    if accepted:
        inputs[safe_name[:60]] = sanitized
    evidence["walkthrough_inputs"] = inputs
    run.evidence_json = evidence
    return sanitized, accepted


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


def _evidence_text(finding: Finding) -> str:
    chunks = [finding.title, finding.esc_category, finding.rule_id, finding.trigger_conditions, finding.simulation_summary]
    chunks.extend(str(item) for item in _as_list((finding.simulation_json or {}).get("preconditions_met")))
    chunks.extend(str(item) for item in _as_list((finding.simulation_json or {}).get("missing_or_unconfirmed")))
    chunks.append(str(finding.evidence_json or {}))
    return " ".join(str(chunk or "") for chunk in chunks).lower()


def _evidence_state(text: str, positive_terms: tuple[str, ...], negative_terms: tuple[str, ...] = ()) -> str:
    if any(term in text for term in negative_terms):
        return "not indicated"
    if any(term in text for term in positive_terms):
        return "indicated"
    return "incomplete"


def build_walkthrough_script(finding: Finding, result: str | None = None) -> list[dict]:
    text = _evidence_text(finding)
    result_value = result or calculate_replay_result(finding)[0]
    result_text = result_label(result_value)
    title = sanitize_replay_value(finding.title or "Finding")
    target = sanitize_replay_value(finding.affected_object or "Affected object not specified")
    trigger = sanitize_replay_value(finding.trigger_conditions or "Trigger conditions were not fully described.")
    summary = sanitize_replay_value(finding.simulation_summary or finding.rationale or "Collected evidence was loaded for review.")
    missing = [sanitize_replay_value(item) for item in _as_list((finding.simulation_json or {}).get("missing_or_unconfirmed")) if _meaningful(item)]
    preconditions = [sanitize_replay_value(item) for item in _as_list((finding.simulation_json or {}).get("preconditions_met")) if _meaningful(item)]

    def line(speaker: str, line_type: str, message: str, **extra) -> dict:
        item = {"type": line_type, "speaker": speaker, "text": sanitize_replay_value(message)}
        item.update(extra)
        return item

    script: list[dict] = [
        line("CertShield", "line", f"Finding loaded: {title}."),
        line("Walkthrough", "continue", "Press Enter to inspect why this matters."),
    ]

    is_esc1 = any(term in text for term in ("esc1", "subject", "san", "client authentication", "requester-controlled", "supply in request"))
    is_esc4 = any(term in text for term in ("esc4", "template acl", "write owner", "write dacl", "genericall", "dangerous write"))
    is_esc6 = any(term in text for term in ("esc6", "requester supplied san", "editf_attributesubjectaltname2", "ca policy"))
    is_esc8 = any(term in text for term in ("esc8", "web enrollment", "relay", "http endpoint", "ntlm"))

    if is_esc1:
        script.extend(
            [
                line("CertShield", "line", "Evidence shows this template may allow a requester to influence subject or SAN values."),
                line(
                    "Input required",
                    "input",
                    "Type a harmless example identity label to use in this walkthrough. Example: privileged-user-demo",
                    name="demo_identity",
                    placeholder="Type demo value only — not executed",
                    validation="safe_text_only",
                ),
                line("CertShield", "line", "Demo identity recorded as walkthrough input only. Nothing was sent to ADCS."),
                line("CertShield", "line", f"Evidence check: Client Authentication capable template: {_evidence_state(text, ('client authentication', 'smart card logon', 'pkinit'), ('no client authentication',))}."),
                line("CertShield", "line", f"Evidence check: Manager approval requirement: {_evidence_state(text, ('manager approval required', 'approval required'), ('no manager approval', 'manager approval disabled'))}."),
                line("CertShield", "line", f"Evidence check: Enrollment permission: {_evidence_state(text, ('enroll', 'autoenroll', 'enrollment permission'), ())}."),
                line("Walkthrough", "continue", "Press Enter to view the simulated risk outcome."),
                line(
                    "CertShield",
                    "result",
                    "Simulated outcome: If an authorized requester abused this configuration, "
                    "the collected evidence indicates a certificate request could potentially represent another identity. "
                    "CertShield did not request a certificate and did not attempt authentication.",
                ),
            ]
        )
    elif is_esc4:
        script.extend(
            [
                line("CertShield", "line", f"Template control path reviewed for {target}."),
                line("CertShield", "line", "Collected evidence indicates dangerous template write or ownership permissions may exist."),
                line("Walkthrough", "choice", "Choose a safe explanation path.", options=["Why write access matters", "What evidence is missing", "Remediation focus"]),
                line("CertShield", "line", "In theory, dangerous template control could alter issuance settings. CertShield made no AD object modifications."),
                line(
                    "CertShield",
                    "result",
                    "Simulated outcome: collected evidence suggests a possible privilege impact if authorized template administrators or delegated principals misused dangerous write permissions. No directory changes were made.",
                ),
            ]
        )
    elif is_esc6:
        script.extend(
            [
                line("CertShield", "line", "CA policy evidence reviewed for requester-supplied SAN behavior."),
                line("CertShield", "line", "Requester-supplied SAN policy can increase abuse potential when combined with permissive templates."),
                line("Walkthrough", "continue", "Press Enter to review the safe simulated impact."),
                line("CertShield", "result", "Simulated outcome: collected evidence suggests requester-controlled SAN policy could amplify identity misuse risk. CertShield made no CA request and changed no CA configuration."),
            ]
        )
    elif is_esc8:
        script.extend(
            [
                line("CertShield", "line", "Web enrollment or endpoint posture evidence was loaded."),
                line("CertShield", "line", "Relay-prone posture can matter when authentication protections are incomplete."),
                line("Walkthrough", "continue", "Press Enter to view the defensive outcome."),
                line("CertShield", "result", "Simulated outcome: collected evidence suggests relay exposure may be present. CertShield attempted no relay and attempted no authentication."),
            ]
        )
    else:
        script.extend(
            [
                line("CertShield", "line", f"Affected object: {target}."),
                line("CertShield", "line", f"Trigger conditions: {trigger}."),
                line("CertShield", "line", f"Evidence summary: {summary}."),
                line("CertShield", "line", "Missing evidence: " + ("; ".join(str(item) for item in missing) if missing else "No material missing evidence recorded.")),
                line("Walkthrough", "choice", "Choose a safe review focus.", options=["Simulated impact", "Evidence gaps", "Remediation steps"]),
                line("CertShield", "result", "Simulated outcome: collected evidence suggests risk may exist, but this remains a defensive, non-executing walkthrough with no live confirmation."),
            ]
        )

    if preconditions:
        script.insert(2, line("CertShield", "line", "Stored trigger evidence: " + "; ".join(str(item) for item in preconditions[:3]) + "."))
    script.append(line("CertShield", "banner", f"RESULT: {result_text}"))
    return script


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
        "Mode: Guided Evidence Walkthrough. Live commands executed: No. Certificate requested: No. Authentication attempted: No. Environment changes: None. This is a safe simulation based on collected evidence.",
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
    result, confidence, summary = calculate_replay_result(finding)
    walkthrough_script = build_walkthrough_script(finding, result)
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
                "walkthrough_script": walkthrough_script,
                "walkthrough_inputs": {},
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
    return db.query(ValidationRun).filter_by(finding_id=finding_id).order_by(ValidationRun.created_at.desc(), ValidationRun.id.desc()).limit(limit).all()


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
