from pydantic import BaseModel, Field

from app.models import AuditStatusEnum, CriticalityEnum, FindingStatusEnum, ResultEnum, RoleEnum, SeverityEnum


class LoginRequest(BaseModel):
    email: str
    org_id: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    expires_in: int = 28800


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)


class OrganizationOut(BaseModel):
    id: str
    name: str


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str


class MembershipOut(BaseModel):
    id: str
    org_id: str
    user_id: str
    role: RoleEnum


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    description: str = ''
    criticality: CriticalityEnum = CriticalityEnum.medium


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    criticality: CriticalityEnum | None = None


class ProjectOut(BaseModel):
    id: str
    org_id: str
    name: str
    description: str
    criticality: CriticalityEnum


class IntegrationCreate(BaseModel):
    provider: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=2, max_length=255)
    config_json: dict = Field(default_factory=dict)
    secret_ref: str | None = None
    is_enabled: bool = True


class IntegrationUpdate(BaseModel):
    name: str | None = None
    config_json: dict | None = None
    secret_ref: str | None = None
    is_enabled: bool | None = None


class IntegrationOut(BaseModel):
    id: str
    org_id: str
    project_id: str
    provider: str
    name: str
    config_json: dict
    secret_ref: str | None
    is_enabled: bool


class ControlCatalogCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    framework: str = Field(min_length=2, max_length=64)
    version: str = Field(min_length=1, max_length=64)
    checksum: str = Field(min_length=8, max_length=128)
    source_path: str = Field(min_length=3, max_length=512)
    is_global: bool = False


class ControlCatalogOut(BaseModel):
    id: str
    org_id: str | None
    name: str
    framework: str
    version: str
    checksum: str
    source_path: str
    is_global: bool


class AuditRunCreate(BaseModel):
    catalog_version: str = 'v1'


class AuditRunOut(BaseModel):
    id: str
    org_id: str
    project_id: str
    status: AuditStatusEnum
    catalog_version: str
    progress_json: dict
    summary_json: dict
    risk_score: float | None
    risk_level: str | None
    report_evidence_id: str | None


class FindingOut(BaseModel):
    id: str
    org_id: str
    project_id: str
    audit_run_id: str
    control_id: str
    title: str
    severity: SeverityEnum
    result: ResultEnum
    confidence: float
    notes: str
    status: FindingStatusEnum
    evidence_refs_json: list


class EvidenceOut(BaseModel):
    id: str
    org_id: str
    project_id: str
    audit_run_id: str | None
    integration_id: str | None
    item_type: str
    name: str
    object_key: str
    sha256: str
    metadata_json: dict


class RemediationTaskOut(BaseModel):
    id: str
    org_id: str
    project_id: str
    audit_run_id: str
    finding_id: str | None
    title: str
    description: str
    status: str


class AuditLogOut(BaseModel):
    id: int
    org_id: str
    actor_user_id: str | None
    action: str
    entity_type: str
    entity_id: str
    payload_json: dict
    prev_hash: str
    entry_hash: str
    created_at: str
