from pydantic import BaseModel, Field


class PermissionIn(BaseModel):
    principal: str
    can_enroll: bool = False
    can_autoenroll: bool = False


class TemplateIn(BaseModel):
    name: str
    display_name: str
    eku: list[str] = Field(default_factory=list)
    enrollee_supplies_subject: bool = False
    manager_approval: bool = False
    authorized_signatures: int = 0
    validity_days: int = 365
    renewal_days: int = 30
    published_to: list[str] = Field(default_factory=list)
    permissions: list[PermissionIn] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class CAIn(BaseModel):
    name: str
    dns_name: str = ""
    status: str = "unknown"
    config: dict = Field(default_factory=dict)


class CertIn(BaseModel):
    request_id: str
    requester: str = ""
    template_name: str = ""
    subject: str = ""
    san: str = ""
    issued_at: str = ""
    expires_at: str = ""
    status: str = "issued"


class CollectorPayload(BaseModel):
    domain_name: str
    source_host: str
    collector_version: str = "legacy"
    cas: list[CAIn] = Field(default_factory=list)
    templates: list[TemplateIn] = Field(default_factory=list)
    issued_certificates: list[CertIn] = Field(default_factory=list)
    assessment_hints: dict = Field(default_factory=dict)
