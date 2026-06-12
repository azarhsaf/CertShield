from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False, default="collector")
    domain_name: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    status: Mapped[str] = mapped_column(String(50), default="completed")
    summary_json: Mapped[dict] = mapped_column(JSON, default=dict)
    coverage_json: Mapped[dict] = mapped_column(JSON, default=dict)

    cas: Mapped[list["CertificateAuthority"]] = relationship(back_populates="scan")
    templates: Mapped[list["CertificateTemplate"]] = relationship(back_populates="scan")
    certificates: Mapped[list["IssuedCertificate"]] = relationship(back_populates="scan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")
    validation_runs: Mapped[list["ValidationRun"]] = relationship(
        back_populates="scan"
    )


class CertificateAuthority(Base):
    __tablename__ = "certificate_authorities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    dns_name: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(50), default="unknown")
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="cas")


class CertificateTemplate(Base):
    __tablename__ = "certificate_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    eku: Mapped[list] = mapped_column(JSON, default=list)
    enrollee_supplies_subject: Mapped[bool] = mapped_column(Boolean, default=False)
    manager_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    authorized_signatures: Mapped[int] = mapped_column(Integer, default=0)
    validity_days: Mapped[int] = mapped_column(Integer, default=365)
    renewal_days: Mapped[int] = mapped_column(Integer, default=30)
    published_to: Mapped[list] = mapped_column(JSON, default=list)
    raw_json: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="templates")
    permissions: Mapped[list["TemplatePermission"]] = relationship(back_populates="template")


class TemplatePermission(Base):
    __tablename__ = "template_permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_id: Mapped[int] = mapped_column(ForeignKey("certificate_templates.id"), nullable=False)
    principal: Mapped[str] = mapped_column(String(255), nullable=False)
    can_enroll: Mapped[bool] = mapped_column(Boolean, default=False)
    can_autoenroll: Mapped[bool] = mapped_column(Boolean, default=False)

    template: Mapped[CertificateTemplate] = relationship(back_populates="permissions")


class IssuedCertificate(Base):
    __tablename__ = "issued_certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    request_id: Mapped[str] = mapped_column(String(100), nullable=False)
    requester: Mapped[str] = mapped_column(String(255), default="")
    template_name: Mapped[str] = mapped_column(String(255), default="")
    subject: Mapped[str] = mapped_column(String(1000), default="")
    san: Mapped[str] = mapped_column(String(1000), default="")
    issued_at: Mapped[str] = mapped_column(String(100), default="")
    expires_at: Mapped[str] = mapped_column(String(100), default="")
    status: Mapped[str] = mapped_column(String(50), default="issued")

    scan: Mapped[Scan] = relationship(back_populates="certificates")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    esc_category: Mapped[str] = mapped_column(String(50), default="General")
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    coverage_state: Mapped[str] = mapped_column(String(30), default="detected")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    affected_object: Mapped[str] = mapped_column(String(255), nullable=False)
    trigger_conditions: Mapped[str] = mapped_column(Text, default="")
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_steps_json: Mapped[list] = mapped_column(JSON, default=list)
    simulation_summary: Mapped[str] = mapped_column(Text, default="")
    simulation_json: Mapped[dict] = mapped_column(JSON, default=dict)
    reference: Mapped[str] = mapped_column(String(500), default="")

    scan: Mapped[Scan] = relationship(back_populates="findings")
    validation_runs: Mapped[list["ValidationRun"]] = relationship(
        back_populates="finding"
    )


class ValidationRun(Base):
    __tablename__ = "validation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id"),
        nullable=False,
        index=True,
    )
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False,
        index=True,
    )
    mode: Mapped[str] = mapped_column(
        String(50),
        default="evidence_replay",
    )
    recipe_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    recipe_version: Mapped[str] = mapped_column(
        String(20),
        default="1.0",
    )
    recipe_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    target: Mapped[str] = mapped_column(
        String(255),
        default="",
    )
    status: Mapped[str] = mapped_column(
        String(30),
        default="queued",
    )
    result: Mapped[str] = mapped_column(
        String(50),
        default="evidence_incomplete",
    )
    confidence: Mapped[str] = mapped_column(
        String(20),
        default="low",
    )
    summary: Mapped[str] = mapped_column(
        Text,
        default="",
    )
    requested_by: Mapped[str] = mapped_column(
        String(100),
        default="unknown",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
    correlation_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    safety_json: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
    )
    evidence_json: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
    )

    finding: Mapped["Finding"] = relationship(
        back_populates="validation_runs"
    )
    scan: Mapped[Scan] = relationship(
        back_populates="validation_runs"
    )
    steps: Mapped[list["ValidationStep"]] = relationship(
        back_populates="validation_run",
        cascade="all, delete-orphan",
        order_by="ValidationStep.sequence",
    )


class ValidationStep(Base):
    __tablename__ = "validation_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    validation_run_id: Mapped[int] = mapped_column(
        ForeignKey("validation_runs.id"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    step_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(30),
        default="info",
    )
    message: Mapped[str] = mapped_column(
        Text,
        default="",
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
    evidence_json: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
    )

    validation_run: Mapped[ValidationRun] = relationship(
        back_populates="steps"
    )


class RiskAcceptance(Base):
    __tablename__ = "risk_acceptances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    object_name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    risk_title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="Medium")
    accepted_by: Mapped[str] = mapped_column(String(100), nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expiry_date: Mapped[str] = mapped_column(String(50), default="")
    business_justification: Mapped[str] = mapped_column(Text, default="")
    compensating_control: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="active")
    scope: Mapped[str] = mapped_column(String(50), default="exact_fingerprint")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class GovernanceEvidence(Base):
    __tablename__ = "governance_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    control_key: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
    )
    category: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    object_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    control_title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="implemented",
    )
    owner: Mapped[str] = mapped_column(
        String(255),
        default="",
    )
    details: Mapped[str] = mapped_column(
        Text,
        default="",
    )
    evidence_reference: Mapped[str] = mapped_column(
        String(1000),
        default="",
    )
    last_reviewed: Mapped[str] = mapped_column(
        String(50),
        default="",
    )
    next_review: Mapped[str] = mapped_column(
        String(50),
        default="",
    )
    updated_by: Mapped[str] = mapped_column(
        String(100),
        default="",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    details_json: Mapped[dict] = mapped_column(JSON, default=dict)
