from dataclasses import dataclass

from app.models.entities import CertificateAuthority, CertificateTemplate


@dataclass
class RuleFinding:
    rule_id: str
    esc_category: str
    title: str
    severity: str
    confidence: str
    coverage_state: str
    trigger_conditions: str
    rationale: str
    evidence: dict
    remediation: str
    remediation_steps: list[str]
    simulation_summary: str
    simulation: dict
    reference: str
    affected_object: str


BROAD_GROUPS = {"authenticated users", "domain users", "everyone"}
CLIENT_AUTH_MARKERS = {"client authentication", "1.3.6.1.5.5.7.3.2"}
ANY_PURPOSE_MARKERS = {"2.5.29.37.0", "any purpose"}
ENROLLMENT_AGENT_MARKERS = {"1.3.6.1.4.1.311.20.2.1", "certificate request agent", "enrollment agent"}


def _eku_contains(eku: list[str], markers: set[str]) -> bool:
    joined = " ".join(eku).lower()
    return any(m in joined for m in markers)


def _has_client_auth(eku: list[str]) -> bool:
    return _eku_contains(eku, CLIENT_AUTH_MARKERS)


def _has_any_purpose(eku: list[str]) -> bool:
    return _eku_contains(eku, ANY_PURPOSE_MARKERS)


def _has_enrollment_agent(eku: list[str]) -> bool:
    return _eku_contains(eku, ENROLLMENT_AGENT_MARKERS)


def _broad_enrollment(template: CertificateTemplate) -> bool:
    for p in template.permissions:
        if p.can_enroll and p.principal.lower() in BROAD_GROUPS:
            return True
    return False


def _simulation(path: str, preconditions: list[str], blast_radius: str, missing: list[str], confidence: str) -> dict:
    return {
        "safe_mode": True,
        "path": path,
        "preconditions_met": preconditions,
        "missing_or_unconfirmed": missing,
        "blast_radius": blast_radius,
        "confidence": confidence,
        "actions_performed": "No exploitation. No certificate request sent. Read-only assessment only.",
    }


def evaluate_templates(templates: list[CertificateTemplate], cas: list[CertificateAuthority]) -> tuple[list[RuleFinding], dict]:
    findings: list[RuleFinding] = []
    coverage = {
        "ESC1-like": "detected",
        "ESC2-like": "detected",
        "ESC3-like": "detected",
        "ESC4-like": "insufficient_data",
        "ESC5-like": "insufficient_data",
        "ESC6-like": "not_assessed",
        "ESC7-like": "not_assessed",
        "ESC8-like": "insufficient_data",
        "Tier-0": "insufficient_data",
    }

    for t in templates:
        broad = _broad_enrollment(t)
        client_auth = _has_client_auth(t.eku)

        # ESC1-like
        if broad and client_auth and t.enrollee_supplies_subject and (not t.manager_approval or t.authorized_signatures == 0):
            remediation_steps = [
                "Remove Authenticated Users / Domain Users from Enroll or AutoEnroll and scope to dedicated PKI enrollment groups.",
                "Disable enrollee-supplied subject/SAN unless a documented business case requires it.",
                "Require issuance approval and/or authorized signatures for high-impact templates.",
            ]
            findings.append(
                RuleFinding(
                    rule_id="ESC1-LIKE-001",
                    esc_category="ESC1-like",
                    title="Authentication-capable template allows requester-controlled identity fields",
                    severity="Critical",
                    confidence="high",
                    coverage_state="detected",
                    trigger_conditions="client auth EKU + broad enroll + enrollee supplies subject + weak approval/signature safeguards",
                    rationale="A low-privileged principal with enrollment access could potentially obtain an authentication-capable certificate with requester-controlled identity data if this template remains unchanged.",
                    evidence={"template": t.name, "eku": t.eku, "manager_approval": t.manager_approval, "authorized_signatures": t.authorized_signatures},
                    remediation="Restrict enrollment scope and remove requester-controlled identity fields on authentication-capable templates.",
                    remediation_steps=remediation_steps,
                    simulation_summary="Potential identity-auth certificate abuse path exists if current template controls remain.",
                    simulation=_simulation(
                        "ESC1-like",
                        ["Broad enroll observed", "Client authentication capability observed", "Requester-controlled subject/SAN observed"],
                        "Domain user-to-authentication identity misuse potential.",
                        ["No live request attempted"],
                        "high",
                    ),
                    reference="SpecterOps ESC guidance (defensive interpretation)",
                    affected_object=t.name,
                )
            )

        # ESC2-like
        if _has_any_purpose(t.eku):
            findings.append(
                RuleFinding(
                    rule_id="ESC2-LIKE-001",
                    esc_category="ESC2-like",
                    title="Template allows Any Purpose / overly broad EKU semantics",
                    severity="High",
                    confidence="medium",
                    coverage_state="detected",
                    trigger_conditions="EKU includes Any Purpose or equivalent broad semantics",
                    rationale="Overly broad EKU scopes can enable certificate use beyond intended identity or service boundaries.",
                    evidence={"template": t.name, "eku": t.eku},
                    remediation="Replace Any Purpose usage with purpose-specific templates and EKUs aligned to least privilege.",
                    remediation_steps=[
                        "Create dedicated templates per business use case.",
                        "Remove Any Purpose OID from templates not explicitly requiring it.",
                        "Review relying-party mapping for impacted cert auth flows.",
                    ],
                    simulation_summary="If left unchanged, broad EKU semantics may enable unintended certificate use paths.",
                    simulation=_simulation("ESC2-like", ["Any Purpose detected"], "Cross-purpose certificate misuse risk.", ["No issuing workflow executed"], "medium"),
                    reference="ADCS hardening best practice",
                    affected_object=t.name,
                )
            )

        # ESC3-like
        if _has_enrollment_agent(t.eku) and broad:
            findings.append(
                RuleFinding(
                    rule_id="ESC3-LIKE-001",
                    esc_category="ESC3-like",
                    title="Enrollment Agent capable template has broad enrollment",
                    severity="High",
                    confidence="medium",
                    coverage_state="detected",
                    trigger_conditions="Enrollment Agent EKU + broad enrollment permissions",
                    rationale="Enrollment agent capability should be tightly restricted; broad access expands potential on-behalf-of misuse exposure.",
                    evidence={"template": t.name, "eku": t.eku},
                    remediation="Scope enrollment agent templates to tightly controlled PKI operator groups and require explicit approvals.",
                    remediation_steps=[
                        "Remove broad principals from Enroll/AutoEnroll.",
                        "Restrict to dedicated, monitored PKI operator group.",
                        "Enable additional approval/signature gates where feasible.",
                    ],
                    simulation_summary="A principal with broad access could potentially influence on-behalf-of enrollment workflows.",
                    simulation=_simulation("ESC3-like", ["Enrollment Agent EKU present", "Broad enrollment detected"], "Potential delegated identity issuance impact.", ["No on-behalf-of request attempted"], "medium"),
                    reference="SpecterOps ESC guidance (defensive interpretation)",
                    affected_object=t.name,
                )
            )

        # Generic hardening findings retained for compatibility
        if t.validity_days > 825:
            findings.append(
                RuleFinding(
                    rule_id="TPL-VALIDITY-001",
                    esc_category="General",
                    title="Excessive certificate validity period",
                    severity="Medium",
                    confidence="high",
                    coverage_state="detected",
                    trigger_conditions="Template validity exceeds recommended enterprise baseline",
                    rationale="Long-lived certificates increase persistence opportunities and delay policy correction.",
                    evidence={"template": t.name, "validity_days": t.validity_days},
                    remediation="Reduce validity period to organizational baseline and align renewal strategy to risk tier.",
                    remediation_steps=["Lower validity period.", "Re-issue on updated template.", "Update PKI governance baseline."],
                    simulation_summary="Long lifetime increases window of misuse if certs are mis-issued.",
                    simulation=_simulation("General", ["Validity > baseline"], "Extended persistence window.", [], "high"),
                    reference="PKI hardening baseline",
                    affected_object=t.name,
                )
            )

    # ESC4/5/6/7/8/Tier0 posture placeholders when data is limited
    informational = [
        ("ESC4-LIKE-NA", "ESC4-like", "Template ACL takeover exposure not fully assessed", "insufficient_data", "Template ACL write rights require richer ACL collection (GenericAll/WriteDACL/WriteOwner)."),
        ("ESC5-LIKE-NA", "ESC5-like", "PKI object control path not fully assessed", "insufficient_data", "PKI AD object control paths require extended directory ACL graph data."),
        ("ESC6-LIKE-NA", "ESC6-like", "CA SAN policy posture not assessed", "not_assessed", "Collector lacks complete CA policy flag coverage in current scan."),
        ("ESC7-LIKE-NA", "ESC7-like", "CA management rights posture not assessed", "not_assessed", "Collector lacks CA role/rights assignment details."),
        ("ESC8-LIKE-NA", "ESC8-like", "Web enrollment / relay posture partially assessed", "insufficient_data", "Collector currently does not inventory IIS/CEP/CES/EPA posture."),
        ("TIER0-LIKE-NA", "Tier-0", "Tier-0 PKI administration posture partially assessed", "insufficient_data", "Need privileged group/delegation mapping for full Tier-0 assessment."),
    ]
    for rid, cat, title, state, rationale in informational:
        findings.append(
            RuleFinding(
                rule_id=rid,
                esc_category=cat,
                title=title,
                severity="Low",
                confidence="low",
                coverage_state=state,
                trigger_conditions="Assessment coverage check",
                rationale=rationale,
                evidence={"cas_seen": len(cas), "templates_seen": len(templates)},
                remediation="Expand collector scope for this category and enforce least-privilege PKI administration.",
                remediation_steps=["Collect missing metadata.", "Validate role assignments.", "Re-run assessment."],
                simulation_summary="Coverage-only result; no exploit action attempted.",
                simulation=_simulation(cat, ["Baseline scan completed"], "Unknown until additional data is collected.", ["Missing required metadata"], "low"),
                reference="Defensive ADCS assessment coverage guidance",
                affected_object="PKI posture",
            )
        )

    return findings, coverage
