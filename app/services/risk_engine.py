import json
from dataclasses import dataclass
from typing import Any

from app.models.entities import CertificateAuthority, CertificateTemplate


@dataclass
class RuleFinding:
    @property
    def evidence_json(self):
        evidence = getattr(self, 'evidence', None)
        if evidence is None:
            evidence = getattr(self, 'evidence_data', None)
        if evidence is None:
            return {}
        if isinstance(evidence, dict):
            return evidence
        if isinstance(evidence, str):
            try:
                return json.loads(evidence)
            except Exception:
                return {'raw': evidence}
        return evidence

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


BROAD_GROUPS = {"authenticated users", "domain users", "everyone", "users", "domain computers"}
PKI_ADMIN_HINTS = {"pki", "cert", "ca admin", "enterprise admin", "domain admin"}
CLIENT_AUTH_MARKERS = {"client authentication", "1.3.6.1.5.5.7.3.2", "smart card logon", "1.3.6.1.4.1.311.20.2.2"}
ANY_PURPOSE_MARKERS = {"2.5.29.37.0", "any purpose"}
ENROLLMENT_AGENT_MARKERS = {"1.3.6.1.4.1.311.20.2.1", "certificate request agent", "enrollment agent"}
DANGEROUS_TEMPLATE_RIGHTS = {"genericall", "genericwrite", "writedacl", "writeowner", "writeproperty", "fullcontrol"}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _eku_contains(eku: list[str], markers: set[str]) -> bool:
    joined = " ".join(eku).lower()
    return any(m in joined for m in markers)


def _has_client_auth(eku: list[str]) -> bool:
    return _eku_contains(eku, CLIENT_AUTH_MARKERS)


def _has_any_purpose(eku: list[str]) -> bool:
    return _eku_contains(eku, ANY_PURPOSE_MARKERS)


def _has_enrollment_agent(eku: list[str]) -> bool:
    return _eku_contains(eku, ENROLLMENT_AGENT_MARKERS)


def _principal_is_broad(principal: str) -> bool:
    principal_name = _norm(principal).split("\\")[-1]
    return principal_name in BROAD_GROUPS


def _principal_is_non_pki_admin(principal: str) -> bool:
    lowered = _norm(principal)
    if _principal_is_broad(principal):
        return True
    return not any(hint in lowered for hint in PKI_ADMIN_HINTS)


def _broad_enrollment(template: CertificateTemplate) -> bool:
    return any(p.can_enroll and _principal_is_broad(p.principal) for p in template.permissions)


def _permission_evidence(template: CertificateTemplate) -> list[dict[str, Any]]:
    return [
        {"principal": p.principal, "can_enroll": p.can_enroll, "can_autoenroll": p.can_autoenroll}
        for p in template.permissions
    ]


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


def _risk_score(severity: str, confidence: str, coverage_state: str) -> int:
    base = {"Critical": 92, "High": 76, "Medium": 52, "Low": 24}.get(severity, 20)
    if confidence == "low":
        base -= 8
    if coverage_state != "detected":
        base = min(base, 20)
    return max(0, min(base, 100))


def _finding(
    *,
    rule_id: str,
    esc_category: str,
    title: str,
    severity: str,
    confidence: str,
    trigger_conditions: str,
    rationale: str,
    evidence: dict,
    remediation: str,
    remediation_steps: list[str],
    simulation_summary: str,
    simulation: dict,
    reference: str,
    affected_object: str,
    coverage_state: str = "detected",
) -> RuleFinding:
    enriched_evidence = {
        **evidence,
        "risk_score": _risk_score(severity, confidence, coverage_state),
        "business_impact": rationale,
        "technical_impact": trigger_conditions,
        "score_breakdown": {"severity": severity, "confidence": confidence, "coverage_state": coverage_state},
    }
    return RuleFinding(
        rule_id=rule_id,
        esc_category=esc_category,
        title=title,
        severity=severity,
        confidence=confidence,
        coverage_state=coverage_state,
        trigger_conditions=trigger_conditions,
        rationale=rationale,
        evidence=enriched_evidence,
        remediation=remediation,
        remediation_steps=remediation_steps,
        simulation_summary=simulation_summary,
        simulation=simulation,
        reference=reference,
        affected_object=affected_object,
    )


def _template_acl_findings(template: CertificateTemplate) -> list[RuleFinding]:
    raw = template.raw_json or {}
    acl_entries = _as_list(raw.get("acl_details")) + _as_list(raw.get("dangerous_acl"))
    findings: list[RuleFinding] = []
    for entry in acl_entries:
        if not isinstance(entry, dict):
            continue
        principal = str(entry.get("principal", ""))
        rights = {_norm(r).replace("_", "") for r in _as_list(entry.get("rights"))}
        if rights & DANGEROUS_TEMPLATE_RIGHTS and _principal_is_non_pki_admin(principal):
            findings.append(
                _finding(
                    rule_id="ESC4-LIKE-001",
                    esc_category="ESC4-like",
                    title="Template object has dangerous writable ACL exposure",
                    severity="High",
                    confidence="high",
                    trigger_conditions="Template ACL includes GenericAll/GenericWrite/WriteDACL/WriteOwner-style rights for a non-PKI-admin principal",
                    rationale="A principal with template modification rights could potentially change template properties and create a more dangerous enrollment path.",
                    evidence={"template": template.name, "principal": principal, "rights": sorted(rights)},
                    remediation="Remove dangerous template object write rights from non-PKI-admin principals and delegate template administration only to dedicated PKI admin groups.",
                    remediation_steps=[
                        "Remove GenericAll / GenericWrite / WriteDACL / WriteOwner from the affected principal.",
                        "Delegate template management through a monitored PKI administration group.",
                        "Re-run CertShield after ACL changes to confirm the exposure is removed.",
                    ],
                    simulation_summary="A writable-template control path is present and could allow unsafe template changes if left unresolved.",
                    simulation=_simulation(
                        "ESC4-like",
                        ["Template ACL write-capable right observed", "Principal is not recognized as a PKI admin group"],
                        "Template takeover could affect any CA publishing or honoring the template.",
                        ["No ACL modification attempted"],
                        "high",
                    ),
                    reference="Defensive ADCS ACL hardening guidance",
                    affected_object=template.name,
                )
            )
    return findings


def _ca_posture_findings(cas: list[CertificateAuthority]) -> tuple[list[RuleFinding], dict[str, str]]:
    findings: list[RuleFinding] = []
    coverage = {
        "ESC5-like": "insufficient_data",
        "ESC6-like": "not_assessed",
        "ESC7-like": "not_assessed",
        "ESC8-like": "insufficient_data",
        "Tier-0": "insufficient_data",
    }

    for ca in cas:
        config = ca.config_json or {}
        ca_name = ca.name

        pki_control_paths = _as_list(config.get("pki_control_paths")) + _as_list(config.get("dangerous_pki_object_control"))
        if pki_control_paths:
            coverage["ESC5-like"] = "detected"
            findings.append(
                _finding(
                    rule_id="ESC5-LIKE-001",
                    esc_category="ESC5-like",
                    title="PKI-related AD object control path detected",
                    severity="High",
                    confidence="medium",
                    trigger_conditions="Collector reported dangerous control over PKI-related AD objects",
                    rationale="Control over PKI container, CA, NTAuth, or related AD objects can alter trust or issuance behavior and should be treated as privileged infrastructure exposure.",
                    evidence={"ca": ca_name, "control_paths": pki_control_paths},
                    remediation="Remove unsafe control paths over PKI-related AD objects and restrict PKI object administration to approved Tier-0 operators.",
                    remediation_steps=[
                        "Review each reported PKI control path and validate business ownership.",
                        "Remove broad or non-PKI-admin GenericAll/GenericWrite/WriteDACL/WriteOwner rights.",
                        "Audit NTAuth, AIA, CDP, Enrollment Services, and template containers after remediation.",
                    ],
                    simulation_summary="A PKI object control path could alter certificate trust or issuance posture if left unresolved.",
                    simulation=_simulation(
                        "ESC5-like",
                        ["Collector reported PKI object control metadata"],
                        "Potential enterprise PKI trust or issuance impact.",
                        ["No directory object changes attempted"],
                        "medium",
                    ),
                    reference="Defensive ADCS object-control hardening guidance",
                    affected_object=ca_name,
                )
            )
        elif config.get("pki_control_paths_assessed") is True:
            coverage["ESC5-like"] = "not_detected"

        san_flag = config.get("editf_attributesubjectaltname2") or config.get("allow_user_supplied_san") or config.get("ca_san_policy_enabled")
        if san_flag is True or _norm(san_flag) in {"true", "enabled", "1"}:
            coverage["ESC6-like"] = "detected"
            findings.append(
                _finding(
                    rule_id="ESC6-LIKE-001",
                    esc_category="ESC6-like",
                    title="CA policy may allow requester-supplied SAN attributes",
                    severity="High",
                    confidence="medium",
                    trigger_conditions="CA configuration indicates EDITF_ATTRIBUTESUBJECTALTNAME2 or equivalent requester-supplied SAN policy",
                    rationale="A CA-level SAN policy can increase impact of otherwise constrained templates by permitting requester-controlled subject alternative name attributes.",
                    evidence={"ca": ca_name, "config": config},
                    remediation="Review and disable dangerous CA policy flags permitting arbitrary SAN attributes where not required.",
                    remediation_steps=[
                        "Validate whether requester-supplied SAN is required by a documented business workflow.",
                        "Disable the CA-level SAN policy flag where not explicitly required.",
                        "Restart CA services during an approved maintenance window if policy changes require it.",
                    ],
                    simulation_summary="If requester-supplied SAN is permitted at CA level, other template controls may be weakened.",
                    simulation=_simulation(
                        "ESC6-like",
                        ["CA SAN policy exposure reported"],
                        "CA-wide policy impact across published templates.",
                        ["No certificate request sent"],
                        "medium",
                    ),
                    reference="Microsoft ADCS policy module hardening guidance",
                    affected_object=ca_name,
                )
            )
        elif config.get("ca_policy_flags_assessed") is True:
            coverage["ESC6-like"] = "not_detected"

        manager_principals = _as_list(config.get("ca_manage_principals")) + _as_list(config.get("manage_ca_principals"))
        broad_ca_manager = bool(config.get("manage_ca_broad")) or any(_principal_is_broad(str(p)) for p in manager_principals)
        if broad_ca_manager:
            coverage["ESC7-like"] = "detected"
            findings.append(
                _finding(
                    rule_id="ESC7-LIKE-001",
                    esc_category="ESC7-like",
                    title="CA management rights appear overly broad",
                    severity="Critical",
                    confidence="medium",
                    trigger_conditions="CA management/approval role metadata includes broad or non-dedicated principals",
                    rationale="CA management and officer rights can alter issuance behavior and should be limited to hardened, monitored PKI operator groups.",
                    evidence={"ca": ca_name, "principals": manager_principals, "manage_ca_broad": config.get("manage_ca_broad")},
                    remediation="Restrict CA management and officer roles to dedicated PKI administrators and review all delegated CA permissions.",
                    remediation_steps=[
                        "Remove broad principals from ManageCA, ManageCertificates, or CA officer assignments.",
                        "Use dedicated PKI admin groups protected as Tier-0 infrastructure.",
                        "Enable auditing for CA administration changes.",
                    ],
                    simulation_summary="Broad CA administration rights could allow changes to CA issuance posture if left unresolved.",
                    simulation=_simulation(
                        "ESC7-like",
                        ["Broad CA management principal reported"],
                        "CA-wide administrative impact.",
                        ["No CA configuration changes attempted"],
                        "medium",
                    ),
                    reference="Defensive ADCS CA role hardening guidance",
                    affected_object=ca_name,
                )
            )
        elif config.get("ca_roles_assessed") is True:
            coverage["ESC7-like"] = "not_detected"

        web_enabled = config.get("web_enrollment_enabled") or config.get("ces_enabled") or config.get("cep_enabled")
        ntlm_enabled = config.get("ntlm_enabled") is not False
        epa_enabled = config.get("epa_enabled") is True
        if web_enabled:
            coverage["ESC8-like"] = "detected"
            severity = "High" if ntlm_enabled and not epa_enabled else "Medium"
            findings.append(
                _finding(
                    rule_id="ESC8-LIKE-001",
                    esc_category="ESC8-like",
                    title="Web enrollment / CES / CEP exposure requires relay-resistance review",
                    severity=severity,
                    confidence="medium",
                    trigger_conditions="Collector reports web enrollment/CES/CEP service exposure",
                    rationale="Certificate enrollment web endpoints should be reviewed for NTLM exposure and relay-resistant protections such as EPA and Kerberos-first authentication.",
                    evidence={"ca": ca_name, "web_enabled": web_enabled, "ntlm_enabled": ntlm_enabled, "epa_enabled": epa_enabled},
                    remediation="Disable unused web enrollment roles, prefer Kerberos, reduce NTLM exposure, and enable protections such as EPA where applicable.",
                    remediation_steps=[
                        "Disable Web Enrollment, CES, or CEP roles if they are not required.",
                        "Prefer Kerberos and reduce NTLM exposure for enrollment endpoints.",
                        "Enable Extended Protection for Authentication (EPA) where supported.",
                    ],
                    simulation_summary="If relay protections are absent and the endpoint is reachable, enrollment services may present relay-prone posture.",
                    simulation=_simulation(
                        "ESC8-like",
                        ["Enrollment web endpoint reported"],
                        "Endpoint-level exposure; impact depends on templates and authentication policy.",
                        ["Endpoint reachability and relay protections not actively tested"],
                        "medium",
                    ),
                    reference="Defensive ADCS web enrollment hardening guidance",
                    affected_object=ca_name,
                )
            )
        elif config.get("web_enrollment_assessed") is True:
            coverage["ESC8-like"] = "not_detected"

        tier0_delegates = _as_list(config.get("delegated_admin_principals")) + _as_list(config.get("tier0_admin_principals"))
        broad_tier0 = config.get("tier0_admin_broad") or any(_principal_is_broad(str(p)) for p in tier0_delegates)
        if broad_tier0:
            coverage["Tier-0"] = "detected"
            findings.append(
                _finding(
                    rule_id="TIER0-PKI-001",
                    esc_category="Tier-0",
                    title="PKI administration path is not sufficiently Tier-0 restricted",
                    severity="High",
                    confidence="medium",
                    trigger_conditions="Collector reports broad or risky delegated administration over CA/PKI components",
                    rationale="ADCS servers, enrollment services, and PKI administrative paths are privileged infrastructure and should be governed as Tier-0 assets.",
                    evidence={"ca": ca_name, "delegated_admin_principals": tier0_delegates, "tier0_admin_broad": config.get("tier0_admin_broad")},
                    remediation="Treat CA servers, enrollment services, and PKI admin paths as privileged infrastructure and reduce delegated administration.",
                    remediation_steps=[
                        "Move PKI administration into Tier-0 governance.",
                        "Remove broad delegated administration from CA servers and PKI objects.",
                        "Monitor changes to CA configuration, templates, and PKI AD objects.",
                    ],
                    simulation_summary="Broad PKI administration expands blast radius for certificate trust and issuance changes.",
                    simulation=_simulation(
                        "Tier-0",
                        ["Broad PKI administration metadata reported"],
                        "Potential enterprise-wide PKI administration impact.",
                        ["No privilege or configuration changes attempted"],
                        "medium",
                    ),
                    reference="Privileged access / Tier-0 PKI governance guidance",
                    affected_object=ca_name,
                )
            )
        elif config.get("tier0_posture_assessed") is True:
            coverage["Tier-0"] = "not_detected"

    return findings, coverage


def _coverage_finding(category: str, state: str, title: str, rationale: str, templates: list[CertificateTemplate], cas: list[CertificateAuthority]) -> RuleFinding:
    return _finding(
        rule_id=f"{category.upper().replace('-', '').replace(' ', '')}-COVERAGE",
        esc_category=category,
        title=title,
        severity="Low",
        confidence="low",
        coverage_state=state,
        trigger_conditions="Assessment coverage check",
        rationale=rationale,
        evidence={"cas_seen": len(cas), "templates_seen": len(templates)},
        remediation="Collect the missing defensive metadata and re-run the assessment before accepting residual risk.",
        remediation_steps=["Expand collector scope for this category.", "Validate the result with PKI administrators.", "Re-run CertShield and compare scan history."],
        simulation_summary="Coverage-only result; no exploitation or live validation performed.",
        simulation=_simulation(category, ["Baseline scan completed"], "Unknown until additional data is collected.", ["Missing required metadata"], "low"),
        reference="Defensive ADCS assessment coverage guidance",
        affected_object="PKI posture",
    )


def evaluate_templates(templates: list[CertificateTemplate], cas: list[CertificateAuthority]) -> tuple[list[RuleFinding], dict]:
    findings: list[RuleFinding] = []
    coverage = {
        "ESC1-like": "not_detected" if templates else "insufficient_data",
        "ESC2-like": "not_detected" if templates else "insufficient_data",
        "ESC3-like": "not_detected" if templates else "insufficient_data",
        "ESC4-like": "insufficient_data",
        "ESC5-like": "insufficient_data",
        "ESC6-like": "not_assessed",
        "ESC7-like": "not_assessed",
        "ESC8-like": "insufficient_data",
        "Tier-0": "insufficient_data",
    }

    for template in templates:
        broad = _broad_enrollment(template)
        client_auth = _has_client_auth(template.eku)
        any_purpose = _has_any_purpose(template.eku)
        enrollment_agent = _has_enrollment_agent(template.eku)

        if broad and client_auth and template.enrollee_supplies_subject and (not template.manager_approval or template.authorized_signatures == 0):
            coverage["ESC1-like"] = "detected"
            findings.append(
                _finding(
                    rule_id="ESC1-LIKE-001",
                    esc_category="ESC1-like",
                    title="Authentication-capable template allows requester-controlled identity fields",
                    severity="Critical",
                    confidence="high",
                    trigger_conditions="Client authentication EKU + broad enrollment + enrollee-supplied subject/SAN + low approval/signature safeguards",
                    rationale="A low-privileged principal with enroll access could potentially obtain an authentication-capable certificate with requester-controlled identity data if this template remains unchanged.",
                    evidence={
                        "template": template.name,
                        "eku": template.eku,
                        "permissions": _permission_evidence(template),
                        "manager_approval": template.manager_approval,
                        "authorized_signatures": template.authorized_signatures,
                    },
                    remediation="Restrict enrollment scope and remove requester-controlled identity fields on authentication-capable templates.",
                    remediation_steps=[
                        "Remove Authenticated Users / Domain Users from Enroll or AutoEnroll and scope to dedicated security groups.",
                        "Disable enrollee-supplied subject/SAN unless a documented business case requires it.",
                        "Remove Client Authentication EKU from templates not intended for identity authentication.",
                        "Use manager approval or authorized signatures only where workflow requirements justify the added control.",
                    ],
                    simulation_summary="A low-privileged principal with enroll access could potentially request an authentication-capable certificate with requester-controlled identity fields if this remains unfixed.",
                    simulation=_simulation(
                        "ESC1-like",
                        ["Broad enrollment observed", "Client authentication capability observed", "Requester-controlled subject/SAN observed"],
                        "Domain user-to-authentication identity misuse potential.",
                        ["No certificate request sent", "No credentials used"],
                        "high",
                    ),
                    reference="SpecterOps ESC-style ADCS defensive assessment guidance; Microsoft ADCS template hardening guidance",
                    affected_object=template.name,
                )
            )

        if any_purpose:
            coverage["ESC2-like"] = "detected"
            findings.append(
                _finding(
                    rule_id="ESC2-LIKE-001",
                    esc_category="ESC2-like",
                    title="Template allows Any Purpose / overly broad EKU semantics",
                    severity="High" if broad else "Medium",
                    confidence="high" if broad else "medium",
                    trigger_conditions="Template EKU contains Any Purpose or equivalent overly broad usage semantics",
                    rationale="Any Purpose or broad EKU semantics can permit certificates to be accepted in unintended authentication or signing contexts.",
                    evidence={"template": template.name, "eku": template.eku, "permissions": _permission_evidence(template)},
                    remediation="Replace Any Purpose / overly broad template use with purpose-specific templates.",
                    remediation_steps=[
                        "Create dedicated templates per certificate use case.",
                        "Remove Any Purpose OID from templates unless explicitly required and formally approved.",
                        "Review relying-party mappings and issuance history for this template.",
                    ],
                    simulation_summary="Broad EKU semantics could allow certificate use beyond the intended business purpose.",
                    simulation=_simulation("ESC2-like", ["Any Purpose / broad EKU detected"], "Cross-purpose certificate misuse risk.", ["No certificate issued or tested"], "high" if broad else "medium"),
                    reference="ADCS EKU hardening guidance; ESC-style defensive assessment guidance",
                    affected_object=template.name,
                )
            )

        if enrollment_agent and broad:
            coverage["ESC3-like"] = "detected"
            findings.append(
                _finding(
                    rule_id="ESC3-LIKE-001",
                    esc_category="ESC3-like",
                    title="Enrollment Agent capable template has broad enrollment",
                    severity="High",
                    confidence="high",
                    trigger_conditions="Enrollment Agent EKU + broad enrollment permissions",
                    rationale="Enrollment Agent capability should be tightly restricted because it can participate in on-behalf-of issuance workflows.",
                    evidence={"template": template.name, "eku": template.eku, "permissions": _permission_evidence(template)},
                    remediation="Scope enrollment agent templates to tightly controlled PKI operator groups and require explicit approval workflows.",
                    remediation_steps=[
                        "Remove broad principals from Enroll/AutoEnroll.",
                        "Restrict to a dedicated, monitored PKI operator group.",
                        "Review enrollment agent issuance history and intended business processes.",
                    ],
                    simulation_summary="A broadly enrollable enrollment-agent template could expose delegated enrollment workflows if left unresolved.",
                    simulation=_simulation(
                        "ESC3-like",
                        ["Enrollment Agent EKU present", "Broad enrollment detected"],
                        "Potential delegated identity issuance impact.",
                        ["No on-behalf-of request attempted"],
                        "high",
                    ),
                    reference="SpecterOps ESC-style ADCS defensive assessment guidance",
                    affected_object=template.name,
                )
            )

        acl_findings = _template_acl_findings(template)
        if acl_findings:
            coverage["ESC4-like"] = "detected"
            findings.extend(acl_findings)
        elif (template.raw_json or {}).get("acl_assessed") is True and coverage["ESC4-like"] != "detected":
            coverage["ESC4-like"] = "not_detected"

        if template.validity_days > 825:
            findings.append(
                _finding(
                    rule_id="TPL-VALIDITY-001",
                    esc_category="General",
                    title="Excessive certificate validity period",
                    severity="Medium",
                    confidence="high",
                    trigger_conditions="Template validity exceeds recommended enterprise baseline",
                    rationale="Long-lived certificates increase persistence opportunities and delay correction if a certificate is mis-issued.",
                    evidence={"template": template.name, "validity_days": template.validity_days},
                    remediation="Reduce validity period to the organizational baseline and align renewal strategy to certificate risk tier.",
                    remediation_steps=["Lower validity period.", "Re-issue affected certificate profiles on updated templates.", "Update PKI governance baseline."],
                    simulation_summary="Long lifetime increases the window of potential misuse if certificates are mis-issued.",
                    simulation=_simulation("General", ["Validity exceeds baseline"], "Extended persistence window.", [], "high"),
                    reference="PKI lifecycle hardening baseline",
                    affected_object=template.name,
                )
            )

    ca_findings, ca_coverage = _ca_posture_findings(cas)
    findings.extend(ca_findings)
    coverage.update(ca_coverage)

    coverage_rationale = {
        "ESC4-like": "Template ACL write rights require collector-provided ACL metadata (GenericAll/GenericWrite/WriteDACL/WriteOwner).",
        "ESC5-like": "PKI AD object control paths require extended directory ACL graph metadata.",
        "ESC6-like": "CA SAN policy exposure requires CA policy flag metadata.",
        "ESC7-like": "CA management exposure requires CA role and permission metadata.",
        "ESC8-like": "Web enrollment posture requires IIS/CES/CEP/NTLM/EPA metadata.",
        "Tier-0": "Tier-0 posture requires privileged group and delegation metadata.",
    }
    for category, state in coverage.items():
        if state in {"insufficient_data", "not_assessed"}:
            findings.append(
                _coverage_finding(
                    category,
                    state,
                    f"{category} coverage is {state.replace('_', ' ')}",
                    coverage_rationale.get(category, "Additional metadata is needed for this category."),
                    templates,
                    cas,
                )
            )

    return findings, coverage
