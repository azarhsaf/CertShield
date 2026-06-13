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
SECRET_MARKERS = (
    "password",
    "secret",
    "token",
    "credential",
    "private key",
    "private_key",
    "ticket",
    "hash",
    "cookie",
    "authorization",
    "bearer",
)
HTML_TAG_PATTERN = re.compile(r"<[^>]*>")
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]+")



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
    """Return a safe display-only walkthrough note value."""
    text = CONTROL_CHAR_PATTERN.sub("", str(value or ""))
    text = HTML_TAG_PATTERN.sub("", text).strip()[:80]
    lowered = text.lower()
    if any(marker in lowered for marker in SECRET_MARKERS):
        return ""
    return text


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


def _display_value(value: object, fallback: str = "not collected") -> str:
    if value in (None, "", [], {}, ()):
        return fallback
    if isinstance(value, bool):
        return "present" if value else "not present"
    if isinstance(value, list | tuple | set):
        items = [str(sanitize_replay_value(item)) for item in value if _meaningful(item)]
        return ", ".join(items[:5]) if items else fallback
    return str(sanitize_replay_value(value))


def _flatten_evidence(value: object, prefix: str = "") -> dict[str, object]:
    flattened: dict[str, object] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = f"{prefix}.{key}" if prefix else str(key)
            flattened[key_text.lower()] = item
            flattened.update(_flatten_evidence(item, key_text))
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value[:20]):
            flattened.update(_flatten_evidence(item, f"{prefix}.{index}" if prefix else str(index)))
    return flattened


def _first_evidence_value(flattened: dict[str, object], terms: tuple[str, ...], fallback: object = None) -> object:
    for key, value in flattened.items():
        if all(term in key for term in terms) and _meaningful(value):
            return value
    return fallback


def _first_text_match(flattened: dict[str, object], terms: tuple[str, ...], fallback: str = "not collected") -> str:
    value = _first_evidence_value(flattened, terms)
    return _display_value(value, fallback)


def _result_badge(result: str) -> str:
    return {
        "exposure_indicated": "POTENTIALLY VULNERABLE",
        "evidence_incomplete": "EVIDENCE INCOMPLETE",
        "no_exposure_indicated": "NO EXPOSURE INDICATED",
    }.get(result, result_label(result).upper())


def _remediation_bullets(finding: Finding) -> list[str]:
    steps = [str(sanitize_replay_value(item)) for item in _as_list(finding.remediation_steps_json) if _meaningful(item)]
    if steps:
        return steps[:3]
    remediation = str(sanitize_replay_value(finding.remediation or "Review and remediate the configuration shown above."))
    parts = [part.strip(" -.") for part in re.split(r"[\n;]+", remediation) if part.strip()]
    return (parts or [remediation])[:3]


def _environment_snapshot(finding: Finding) -> dict[str, str]:
    evidence = finding.evidence_json or {}
    simulation = finding.simulation_json or {}
    flat = _flatten_evidence({"evidence": evidence, "simulation": simulation})
    target = _display_value(finding.affected_object, "affected object not collected")
    return {
        "title": _display_value(finding.title, "finding title not collected"),
        "target": target,
        "template": _first_text_match(flat, ("template", "name"), target),
        "ca": _first_text_match(flat, ("ca", "name"), _first_text_match(flat, ("published",), "not collected")),
        "dns": _first_text_match(flat, ("dns",), "not collected"),
        "eku": _first_text_match(flat, ("eku",), _first_text_match(flat, ("purpose",), "not collected")),
        "approval": _first_text_match(flat, ("manager", "approval"), "not collected"),
        "subject": _first_text_match(flat, ("subject",), "not collected"),
        "san": _first_text_match(flat, ("san",), "not collected"),
        "permissions": _first_text_match(flat, ("permission",), _first_text_match(flat, ("principal",), "not collected")),
        "severity": _display_value(finding.severity, "not collected"),
        "confidence": _display_value(finding.confidence, "not collected"),
        "summary": _display_value(finding.simulation_summary or finding.rationale, "not collected"),
        "missing": _display_value(simulation.get("missing_or_unconfirmed"), "none recorded"),
        "trigger": _display_value(finding.trigger_conditions, "not collected"),
    }


def _line(speaker: str, line_type: str, text: str, **extra) -> dict:
    item = {"type": line_type, "speaker": speaker, "text": sanitize_replay_value(text)}
    item.update(extra)
    return item


def build_walkthrough_script(finding: Finding, result: str | None = None) -> list[dict]:
    text = _evidence_text(finding)
    result_value = result or calculate_replay_result(finding)[0]
    env = _environment_snapshot(finding)
    script: list[dict] = [
        _line("certshield", "line", "Loading finding from CertShield database."),
        _line("certshield", "line", f"Finding: {env['title']}"),
        _line("certshield", "line", f"Severity: {env['severity']} · Confidence: {env['confidence']}"),
        _line("operator", "continue", "Press Enter to load collected environment evidence."),
    ]

    is_esc1 = any(term in text for term in ("esc1", "subject", "san", "client authentication", "requester-controlled", "supply in request"))
    is_esc4 = any(term in text for term in ("esc4", "template acl", "write owner", "write dacl", "genericall", "dangerous write"))
    is_esc6 = any(term in text for term in ("esc6", "requester supplied san", "editf_attributesubjectaltname2", "ca policy"))
    is_esc8 = any(term in text for term in ("esc8", "web enrollment", "relay", "http endpoint", "ntlm"))

    if is_esc1:
        script.extend(
            [
                _line("certshield", "line", f"Template loaded: {env['template']}"),
                _line("certshield", "line", f"CA: {env['ca']}"),
                _line("certshield", "line", f"CA DNS: {env['dns']}"),
                _line("certshield", "line", f"EKU: {env['eku']}"),
                _line("certshield", "line", f"Manager approval: {env['approval']}"),
                _line("certshield", "line", f"Requester-controlled subject: {env['subject']}"),
                _line("certshield", "line", f"Requester-controlled SAN: {env['san']}"),
                _line("certshield", "line", f"Enrollment access: {env['permissions']}"),
                _line("input", "input", "Type a demo identity label to test the exposure path:", name="demo_identity"),
                _line("certshield", "line", "Demo identity accepted for simulation only."),
                _line("certshield", "line", "Nothing was sent to the CA."),
                _line("operator", "continue", "Press Enter to preview the simulated operator intent."),
                _line("", "simulated", f"[SIMULATED] Build request preview for template {env['template']}"),
                _line("", "simulated", "[SIMULATED] Requested identity label: {{demo_identity}}"),
                _line("", "simulated", f"[SIMULATED] Approval check: {env['approval']}"),
                _line("", "simulated", f"[SIMULATED] Enrollment check: {env['permissions']}"),
                _line("", "simulated", f"[SIMULATED] Evaluate client authentication capability from EKU: {env['eku']}"),
                _line("certshield", "line", "Exposure path indicated."),
            ]
        )
    elif is_esc4:
        script.extend(
            [
                _line("certshield", "line", f"Template loaded: {env['template']}"),
                _line("certshield", "line", f"Dangerous template ACL evidence: {env['permissions']}"),
                _line("input", "input", "Type a demo change label for the simulated preview:", name="demo_change"),
                _line("certshield", "line", "Demo change label accepted for simulation only."),
                _line("", "simulated", f"[SIMULATED] Inspect write permission on template {env['template']}"),
                _line("", "simulated", "[SIMULATED] Preview dangerous template change label: {{demo_change}}"),
                _line("", "simulated", "[SIMULATED] Evaluate whether write access could create an exposure path"),
                _line("certshield", "line", "No AD object was modified."),
            ]
        )
    elif is_esc6:
        script.extend(
            [
                _line("certshield", "line", f"CA loaded: {env['ca']}"),
                _line("certshield", "line", f"CA DNS: {env['dns']}"),
                _line("certshield", "line", f"Requester-supplied SAN policy evidence: {env['san']}"),
                _line("operator", "continue", "Press Enter to preview SAN influence risk."),
                _line("", "simulated", f"[SIMULATED] Inspect CA policy for {env['ca']}"),
                _line("", "simulated", "[SIMULATED] Preview requester-controlled SAN influence risk"),
                _line("", "simulated", "[SIMULATED] Evaluate impact without submitting a CA request"),
                _line("certshield", "line", "No CA request was made."),
            ]
        )
    elif is_esc8:
        script.extend(
            [
                _line("certshield", "line", f"Endpoint evidence: {env['target']}"),
                _line("certshield", "line", f"CA: {env['ca']}"),
                _line("certshield", "line", f"DNS: {env['dns']}"),
                _line("operator", "continue", "Press Enter to preview relay-prone posture."),
                _line("", "simulated", "[SIMULATED] Inspect endpoint posture from collected evidence"),
                _line("", "simulated", "[SIMULATED] Preview relay-prone condition"),
                _line("", "simulated", "[SIMULATED] Evaluate risk without network traffic or authentication"),
                _line("certshield", "line", "No relay was attempted."),
            ]
        )
    else:
        script.extend(
            [
                _line("certshield", "line", f"Affected object: {env['target']}"),
                _line("certshield", "line", f"Trigger: {env['trigger']}"),
                _line("certshield", "line", f"Evidence summary: {env['summary']}"),
                _line("certshield", "line", f"Missing evidence: {env['missing']}"),
                _line("operator", "continue", "Press Enter to preview the simulated risk result."),
                _line("", "simulated", "[SIMULATED] Evaluate finding using collected evidence only"),
                _line("", "simulated", f"[SIMULATED] Result calculation: {_result_badge(result_value)}"),
            ]
        )

    script.extend(
        [
            _line("certshield", "line", "Based on collected evidence, a similar sequence could potentially allow identity misuse if performed by an authorized requester."),
            _line("certshield", "line", "CertShield did not request a certificate."),
            _line("certshield", "line", "CertShield did not authenticate."),
            _line("certshield", "line", "No environment changes were made."),
            _line("certshield", "final", "Nothing was executed. This was a simulation using your collected PKI evidence."),
            _line(
                "certshield",
                "final",
                "However, the names, template settings, CA evidence, and permission indicators shown above came from your environment. "
                "If a real attacker or authorized requester followed a similar abuse path outside CertShield, this configuration could be risky.",
            ),
        ]
    )
    for bullet in _remediation_bullets(finding):
        script.append(_line("certshield", "remediation", f"Remediation: {bullet}"))
    script.append(_line("certshield", "banner", f"RESULT: {_result_badge(result_value)}"))
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
