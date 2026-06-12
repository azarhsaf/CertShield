from pydantic import BaseModel


class ValidationStepResponse(BaseModel):
    id: int
    sequence: int
    step_name: str
    status: str
    message: str
    started_at: str | None = None
    completed_at: str | None = None
    evidence: dict


class ValidationRunResponse(BaseModel):
    id: int
    finding_id: int
    finding_url: str
    scan_id: int
    mode: str
    recipe_id: str
    recipe_version: str
    recipe_hash: str
    target: str
    status: str
    result: str
    result_label: str
    confidence: str
    summary: str
    requested_by: str
    created_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    correlation_id: str
    safety: dict
    evidence: dict
    steps: list[ValidationStepResponse]
