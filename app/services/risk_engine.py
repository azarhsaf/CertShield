from dataclasses import dataclass

from app.models.entities import CertificateTemplate


@dataclass
class RuleFinding:
    rule_id: str
    title: str
    severity: str
    rationale: str
    evidence: dict
    remediation: str
    reference: str
    affected_object: str


BROAD_GROUPS = {"authenticated users", "domain users", "everyone"}


def _has_client_auth(eku: list[str]) -> bool:
    joined = " ".join(eku).lower()
    return "client authentication" in joined or "1.3.6.1.5.5.7.3.2" in joined


def _is_broad_permission(template: CertificateTemplate) -> bool:
    for p in template.permissions:
        if p.can_enroll and p.principal.lower() in BROAD_GROUPS:
            return True
    return False


def evaluate_templates(templates: list[CertificateTemplate]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for t in templates:
        broad = _is_broad_permission(t)
        client_auth = _has_client_auth(t.eku)
        if broad and client_auth and t.enrollee_supplies_subject and not t.manager_approval and t.authorized_signatures == 0:
            findings.append(
                RuleFinding(
                    rule_id="ESC-LIKE-001",
                    title="ESC-style dangerous enrollment combination",
                    severity="Critical",
                    rationale="Template allows broad enrollment with client auth and requester-controlled subject without approval.",
                    evidence={"template": t.name, "eku": t.eku, "permissions": [p.principal for p in t.permissions]},
                    remediation="Restrict enroll permissions, require manager approval or authorized signatures, and disable subject supply.",
                    reference="https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/",
                    affected_object=t.name,
                )
            )
        if t.validity_days > 825:
            findings.append(
                RuleFinding(
                    rule_id="TPL-VALIDITY-001",
                    title="Excessive certificate validity period",
                    severity="Medium",
                    rationale="Long-lived certificates increase persistence and reduce agility.",
                    evidence={"template": t.name, "validity_days": t.validity_days},
                    remediation="Reduce validity period to organizational baseline (e.g., 398 days for client certs).",
                    reference="Internal PKI hardening baseline",
                    affected_object=t.name,
                )
            )
        if broad and not t.manager_approval and client_auth:
            findings.append(
                RuleFinding(
                    rule_id="TPL-APPROVAL-001",
                    title="Powerful template lacks approval safeguards",
                    severity="High",
                    rationale="Broad enrollment on a client auth template without manager approval elevates abuse risk.",
                    evidence={"template": t.name, "manager_approval": t.manager_approval},
                    remediation="Enable approval workflow and narrow enrollment groups.",
                    reference="https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/",
                    affected_object=t.name,
                )
            )
        if t.published_to and len(t.published_to) > 5:
            findings.append(
                RuleFinding(
                    rule_id="CA-PUBLISH-001",
                    title="Template published to unusually high number of CAs",
                    severity="Low",
                    rationale="Broad publication can indicate governance drift or unnecessary exposure.",
                    evidence={"template": t.name, "published_to": t.published_to},
                    remediation="Validate publication scope and remove template from non-essential CAs.",
                    reference="PKI governance best practice",
                    affected_object=t.name,
                )
            )
    return findings
