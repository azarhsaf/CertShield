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
        return [sanitize_replay_value(item, depth + 1) for item in value[:100]]
    if isinstance(value, tuple):
        return [sanitize_replay_value(item, depth + 1) for item in value[:100]]
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


def _bool_state(value: object, true_label: str = "detected", false_label: str = "not detected") -> str:
    if value is None:
        return "incomplete"
    return true_label if bool(value) else false_label


def _matching_template(finding: Finding):
    scan = finding.scan
    if not scan:
        return None
    candidates = list(getattr(scan, "templates", []) or [])
    if not candidates:
        return None
    needles = {
        str(finding.affected_object or "").casefold(),
        str((finding.evidence_json or {}).get("template") or "").casefold(),
        str((finding.evidence_json or {}).get("template_name") or "").casefold(),
        str((finding.evidence_json or {}).get("name") or "").casefold(),
    }
    needles = {item for item in needles if item}
    for template in candidates:
        names = {str(template.name or "").casefold(), str(template.display_name or "").casefold()}
        if needles & names:
            return template
    for template in candidates:
        if str(template.name or "").casefold() in str(finding.affected_object or "").casefold():
            return template
    return candidates[0]


def _ca_for_template(finding: Finding, template) -> object | None:
    scan = finding.scan
    if not scan:
        return None
    cas = list(getattr(scan, "cas", []) or [])
    if not cas:
        return None
    published = {str(item).casefold() for item in _as_list(getattr(template, "published_to", [])) if _meaningful(item)} if template else set()
    for ca in cas:
        if str(ca.name or "").casefold() in published:
            return ca
    evidence_ca = str((finding.evidence_json or {}).get("ca") or (finding.evidence_json or {}).get("ca_name") or "").casefold()
    for ca in cas:
        if evidence_ca and evidence_ca == str(ca.name or "").casefold():
            return ca
    return cas[0]


def _enrollment_principals(template) -> str:
    if not template:
        return "incomplete"
    principals = [perm.principal for perm in getattr(template, "permissions", []) if getattr(perm, "can_enroll", False) or getattr(perm, "can_autoenroll", False)]
    return ", ".join(principals[:5]) if principals else "incomplete"


def _dangerous_acl(template, finding: Finding) -> tuple[str, str]:
    raw = getattr(template, "raw_json", {}) if template else {}
    details = _as_list(raw.get("acl_details") if isinstance(raw, dict) else [])
    for item in details:
        if isinstance(item, dict):
            principal = _display_value(item.get("principal"), "incomplete")
            rights = _display_value(item.get("rights"), "incomplete")
            if principal != "incomplete" or rights != "incomplete":
                return principal, rights
    evidence = finding.evidence_json or {}
    return _display_value(evidence.get("principal"), "incomplete"), _display_value(evidence.get("rights") or evidence.get("permission"), "incomplete")


def _environment_snapshot(finding: Finding) -> dict[str, str]:
    evidence = finding.evidence_json or {}
    simulation = finding.simulation_json or {}
    flat = _flatten_evidence({"evidence": evidence, "simulation": simulation})
    template = _matching_template(finding)
    ca = _ca_for_template(finding, template)
    dangerous_principal, dangerous_permission = _dangerous_acl(template, finding)
    published_to = _as_list(getattr(template, "published_to", [])) if template else []
    eku = _as_list(getattr(template, "eku", [])) if template else _as_list(evidence.get("eku") or evidence.get("purpose"))
    client_auth = any("client authentication" in str(item).casefold() or "1.3.6.1.5.5.7.3.2" in str(item) for item in eku)
    manager_approval = getattr(template, "manager_approval", None) if template else _first_evidence_value(flat, ("manager", "approval"))
    authorized_signatures = getattr(template, "authorized_signatures", None) if template else _first_evidence_value(flat, ("authorized", "signature"))
    supplies_subject = getattr(template, "enrollee_supplies_subject", None) if template else _first_evidence_value(flat, ("subject",))
    ca_config = getattr(ca, "config_json", {}) if ca else {}
    policy_flag = _first_text_match(_flatten_evidence(ca_config), ("san",), "incomplete") if ca_config else _first_text_match(flat, ("san",), "incomplete")
    return {
        "domain": _display_value(getattr(getattr(finding, "scan", None), "domain_name", None), "incomplete"),
        "title": _display_value(finding.title, "incomplete"),
        "target": _display_value(finding.affected_object, "incomplete"),
        "template": _display_value(getattr(template, "name", None), _display_value(finding.affected_object, "incomplete")),
        "template_display": _display_value(getattr(template, "display_name", None), "incomplete"),
        "ca": _display_value(getattr(ca, "name", None), "incomplete"),
        "dns": _display_value(getattr(ca, "dns_name", None), "incomplete"),
        "published": "yes" if published_to else "incomplete",
        "eku": _display_value(eku, "incomplete"),
        "client_auth": _bool_state(client_auth if eku else None),
        "approval": "required" if manager_approval is True else "not required" if manager_approval is False else "incomplete",
        "authorized_signatures": "required" if (authorized_signatures or 0) > 0 else "not required" if authorized_signatures is not None else "incomplete",
        "subject": _bool_state(supplies_subject),
        "san": _first_text_match(flat, ("san",), _bool_state(supplies_subject)),
        "permissions": _enrollment_principals(template),
        "dangerous_principal": dangerous_principal,
        "dangerous_permission": dangerous_permission,
        "policy_flag": policy_flag,
        "severity": _display_value(finding.severity, "incomplete"),
        "confidence": _display_value(finding.confidence, "incomplete"),
        "summary": _display_value(finding.simulation_summary or finding.rationale, "incomplete"),
        "missing": _display_value(simulation.get("missing_or_unconfirmed"), "incomplete"),
        "trigger": _display_value(finding.trigger_conditions, "incomplete"),
    }


def _line(speaker: str, line_type: str, text: str, **extra) -> dict:
    item = {"type": line_type, "speaker": speaker, "text": sanitize_replay_value(text)}
    item.update(extra)
    return item


def _cmd(command: str) -> dict:
    return _line("operator", "command", f"operator@certshield:~$ {command}")


def _kv(label: str, value: str) -> dict:
    return _line("", "line", f"    {label:<31}: {value}")


def _control(expected: str, text: str) -> dict:
    return _line("input", "control", text, expected=expected)


def build_walkthrough_script(finding: Finding, result: str | None = None) -> list[dict]:
    text = _evidence_text(finding)
    result_value = result or calculate_replay_result(finding)[0]
    result_badge = _result_badge(result_value)
    env = _environment_snapshot(finding)
    script: list[dict] = [
        _cmd("certipy-ad find --replay-from-certshield-evidence"),
        _line("", "line", "[+] Domain loaded"),
        _kv("Domain", env["domain"]),
        _kv("CA", env["ca"]),
        _kv("CA DNS", env["dns"]),
        _kv("Template", env["template"]),
        _kv("Published on CA", env["published"]),
        _kv("Enrollment principal", env["permissions"]),
        _line("", "line", "[+] Finding context"),
        _kv("Severity", env["severity"]),
        _kv("Confidence", env["confidence"]),
    ]

    is_esc1 = any(term in text for term in ("esc1", "subject", "san", "client authentication", "requester-controlled", "supply in request"))
    is_esc4 = any(term in text for term in ("esc4", "template acl", "write owner", "write dacl", "genericall", "dangerous write"))
    is_esc6 = any(term in text for term in ("esc6", "requester supplied san", "editf_attributesubjectaltname2", "ca policy"))
    is_esc8 = any(term in text for term in ("esc8", "web enrollment", "relay", "http endpoint", "ntlm"))

    if is_esc1:
        script.extend(
            [
                _line("", "line", "[+] Template indicators"),
                _kv("Client Authentication EKU", env["client_auth"]),
                _kv("EKU", env["eku"]),
                _kv("Enrollee supplies subject", env["subject"]),
                _kv("Requester-controlled SAN", env["san"]),
                _kv("Manager approval", env["approval"]),
                _kv("Authorized signatures", env["authorized_signatures"]),
                _control("ANALYZE", "Type ANALYZE to inspect the template abuse path:"),
                _cmd("certipy-ad analyze-template --replay-from-certshield-evidence"),
                _line("", "line", "[+] Abuse preconditions"),
                _kv("Enrollment allowed", "detected" if env["permissions"] != "incomplete" else "incomplete"),
                _kv("Identity can be influenced", "detected" if env["subject"] == "detected" or env["san"] == "detected" else "incomplete"),
                _kv("Auth-capable certificate", env["client_auth"]),
                _kv("Approval barrier", "not detected" if env["approval"] == "not required" else "detected" if env["approval"] == "required" else "incomplete"),
                _line("", "warning", "[!] Exposure path indicated"),
                _line("", "line", "    Collected evidence suggests this template may allow identity-bearing certificate misuse."),
                _control("REQUEST", "Type REQUEST to replay the certificate request stage:"),
                _cmd(f"certipy-ad req --replay-from-certshield-evidence --template {env['template']} --ca {env['ca']}"),
                _line("", "replay", f"[REPLAY] Target CA       : {env['ca']}"),
                _line("", "replay", f"[REPLAY] Template        : {env['template']}"),
                _line("", "replay", "[REPLAY] Identity field  : requester-controlled evidence indicated"),
                _line("", "replay", "[REPLAY] Request status  : not sent"),
                _line("", "replay", "[REPLAY] Certificate     : not created"),
                _line("", "replay", "[REPLAY] Private key     : not created"),
                _control("AUTH", "Type AUTH to replay the authentication impact stage:"),
                _cmd("certipy-ad auth --replay-from-certshield-evidence"),
                _line("", "replay", "[REPLAY] Certificate authentication path evaluated from collected evidence"),
                _line("", "replay", "[REPLAY] Authentication attempt : not performed"),
                _line("", "replay", "[REPLAY] Logon session          : not created"),
            ]
        )
    elif is_esc4:
        script.extend(
            [
                _control("ANALYZE", "Type ANALYZE to inspect the template ACL path:"),
                _cmd("certipy-ad template --replay-from-certshield-evidence"),
                _line("", "line", "[+] Template ACL indicators"),
                _kv("Template", env["template"]),
                _kv("Dangerous principal", env["dangerous_principal"]),
                _kv("Dangerous permission", env["dangerous_permission"]),
                _line("", "warning", "[!] Template-control exposure may be possible from collected ACL evidence."),
                _control("REQUEST", "Type REQUEST to replay a template-change preview:"),
                _line("", "replay", "[REPLAY] Template change preview : not written"),
                _line("", "replay", "[REPLAY] AD modification         : not performed"),
                _control("AUTH", "Type AUTH to replay downstream impact evaluation:"),
                _line("", "replay", "[REPLAY] Downstream authentication impact evaluated from evidence only"),
            ]
        )
    elif is_esc6:
        script.extend(
            [
                _control("ANALYZE", "Type ANALYZE to inspect CA SAN policy:"),
                _cmd("certipy-ad ca --replay-from-certshield-evidence"),
                _line("", "line", "[+] CA policy indicators"),
                _kv("CA", env["ca"]),
                _kv("Policy flag", env["policy_flag"]),
                _kv("Requester-supplied SAN", env["san"]),
                _line("", "warning", "[!] CA policy may amplify requester-controlled SAN risk."),
                _control("REQUEST", "Type REQUEST to replay a CA request preview:"),
                _line("", "replay", "[REPLAY] CA request      : not sent"),
                _line("", "replay", "[REPLAY] Certificate     : not created"),
                _control("AUTH", "Type AUTH to replay authentication impact evaluation:"),
                _line("", "replay", "[REPLAY] Authentication attempt : not performed"),
            ]
        )
    elif is_esc8:
        script.extend(
            [
                _control("ANALYZE", "Type ANALYZE to inspect relay-prone posture:"),
                _cmd("certipy-ad relay --replay-from-certshield-evidence"),
                _line("", "line", "[+] Endpoint indicators"),
                _kv("Endpoint", env["target"]),
                _kv("CA", env["ca"]),
                _kv("DNS", env["dns"]),
                _line("", "warning", "[!] Relay-prone condition evaluated from collected endpoint posture."),
                _control("REQUEST", "Type REQUEST to replay endpoint request impact:"),
                _line("", "replay", "[REPLAY] Network traffic : not generated"),
                _line("", "replay", "[REPLAY] Relay attempt   : not performed"),
                _control("AUTH", "Type AUTH to replay authentication impact evaluation:"),
                _line("", "replay", "[REPLAY] Authentication attempt : not performed"),
            ]
        )
    else:
        script.extend(
            [
                _control("ANALYZE", "Type ANALYZE to inspect the collected finding evidence:"),
                _line("", "line", "[+] Generic finding indicators"),
                _kv("Affected object", env["target"]),
                _kv("Trigger", env["trigger"]),
                _kv("Evidence summary", env["summary"]),
                _kv("Missing evidence", env["missing"]),
                _control("REQUEST", "Type REQUEST to replay risk calculation:"),
                _line("", "replay", "[REPLAY] Risk calculation evaluated from stored evidence only"),
                _control("AUTH", "Type AUTH to replay possible authentication impact:"),
                _line("", "replay", "[REPLAY] Authentication attempt : not performed"),
            ]
        )

    script.extend(
        [
            _line("certshield", "banner", f"RESULT: {result_badge}"),
            _control("FIX", "Type FIX to view remediation:"),
        ]
    )
    for bullet in _remediation_bullets(finding):
        script.append(_line("certshield", "remediation", f"- {bullet}"))
    script.extend(
        [
            _line("certshield", "final", "Replay complete. No certificate was requested, no authentication was attempted, and no environment change was made."),
            _line(
                "certshield",
                "final",
                "The CA, template, EKU, approval, and permission indicators shown above came from this environment. "
                "A real attacker or authorized requester following a similar path outside CertShield may be able to misuse this configuration.",
            ),
        ]
    )
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
        environment_id=finding.scan.environment_id if finding.scan else None,
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
