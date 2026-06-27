from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class MonitoringAuditStatus(BaseModel):
    success_enabled: bool = False
    failure_enabled: bool = False
    audit_filter: int | None = None
    audit_ready: bool = False
    raw_policy: str = ""


class MonitoringHeartbeatPayload(BaseModel):
    agent_key: str = Field(min_length=8, max_length=128)
    environment_id: int
    hostname: str = Field(min_length=1, max_length=255)
    ca_name: str = Field(default="", max_length=255)
    version: str = Field(default="1.0.0", max_length=50)
    audit: MonitoringAuditStatus = Field(
        default_factory=MonitoringAuditStatus
    )
    capabilities: list[str] = Field(default_factory=list)
    active_session_count: int | None = None
    web_enrollment_user_count: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class MonitoringEventPayload(BaseModel):
    event_key: str = Field(min_length=4, max_length=255)
    category: str = Field(max_length=50)
    event_type: str = Field(max_length=100)
    severity: str = Field(default="info", max_length=30)
    title: str = Field(max_length=255)
    summary: str = ""
    actor: str = Field(default="", max_length=255)
    source_ip: str = Field(default="", max_length=100)
    occurred_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)


class MonitoringEventBatchPayload(BaseModel):
    agent_key: str = Field(min_length=8, max_length=128)
    events: list[MonitoringEventPayload] = Field(
        default_factory=list,
        max_length=500,
    )


class MonitoringMetricPayload(BaseModel):
    agent_key: str = Field(min_length=8, max_length=128)
    occurred_at: datetime
    cpu_percent: float | None = None
    memory_percent: float | None = None
    disk_free_percent: float | None = None
    certsvc_state: str = Field(default="", max_length=50)
    iis_state: str = Field(default="", max_length=50)
    details: dict[str, Any] = Field(default_factory=dict)


class MonitoringCommandResultPayload(BaseModel):
    success: bool
    message: str = ""
    audit: MonitoringAuditStatus | None = None
    details: dict[str, Any] = Field(default_factory=dict)
