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

    cas: Mapped[list["CertificateAuthority"]] = relationship(back_populates="scan")
    templates: Mapped[list["CertificateTemplate"]] = relationship(back_populates="scan")
    certificates: Mapped[list["IssuedCertificate"]] = relationship(back_populates="scan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")


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
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    affected_object: Mapped[str] = mapped_column(String(255), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    reference: Mapped[str] = mapped_column(String(500), default="")

    scan: Mapped[Scan] = relationship(back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    details_json: Mapped[dict] = mapped_column(JSON, default=dict)
