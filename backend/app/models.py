from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


def uuid_str() -> str:
    return str(uuid.uuid4())


class RoleEnum(str, enum.Enum):
    org_admin = 'org_admin'
    auditor = 'auditor'
    client_viewer = 'client_viewer'


class CriticalityEnum(str, enum.Enum):
    low = 'low'
    medium = 'medium'
    high = 'high'


class AuditStatusEnum(str, enum.Enum):
    queued = 'queued'
    running = 'running'
    completed = 'completed'
    failed = 'failed'


class FindingStatusEnum(str, enum.Enum):
    open = 'open'
    accepted = 'accepted'
    resolved = 'resolved'


class SeverityEnum(str, enum.Enum):
    low = 'low'
    medium = 'medium'
    high = 'high'


class ResultEnum(str, enum.Enum):
    passed = 'pass'
    failed = 'fail'
    partial = 'partial'


class Organization(Base):
    __tablename__ = 'organizations'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class User(Base):
    __tablename__ = 'users'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Membership(Base):
    __tablename__ = 'memberships'
    __table_args__ = (UniqueConstraint('org_id', 'user_id', name='uq_membership_org_user'),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey('users.id', ondelete='CASCADE'))
    role: Mapped[RoleEnum] = mapped_column(Enum(RoleEnum), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Project(Base):
    __tablename__ = 'projects'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default='')
    criticality: Mapped[CriticalityEnum] = mapped_column(Enum(CriticalityEnum), default=CriticalityEnum.medium)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Integration(Base):
    __tablename__ = 'integrations'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey('projects.id', ondelete='CASCADE'), index=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    secret_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ControlCatalog(Base):
    __tablename__ = 'control_catalogs'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    checksum: Mapped[str] = mapped_column(String(128), nullable=False)
    source_path: Mapped[str] = mapped_column(String(512), nullable=False)
    is_global: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AuditRun(Base):
    __tablename__ = 'audit_runs'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey('projects.id', ondelete='CASCADE'), index=True)
    triggered_by_user_id: Mapped[str] = mapped_column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    status: Mapped[AuditStatusEnum] = mapped_column(Enum(AuditStatusEnum), default=AuditStatusEnum.queued, index=True)
    catalog_version: Mapped[str] = mapped_column(String(64), default='v1')
    progress_json: Mapped[dict] = mapped_column(JSON, default=dict)
    summary_json: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    report_evidence_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('evidence_items.id', ondelete='SET NULL'), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class Finding(Base):
    __tablename__ = 'findings'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey('projects.id', ondelete='CASCADE'), index=True)
    audit_run_id: Mapped[str] = mapped_column(String(36), ForeignKey('audit_runs.id', ondelete='CASCADE'), index=True)
    control_id: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[SeverityEnum] = mapped_column(Enum(SeverityEnum), default=SeverityEnum.medium)
    result: Mapped[ResultEnum] = mapped_column(
        Enum(ResultEnum, values_callable=lambda enum_cls: [member.value for member in enum_cls]),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    notes: Mapped[str] = mapped_column(Text, default='')
    status: Mapped[FindingStatusEnum] = mapped_column(Enum(FindingStatusEnum), default=FindingStatusEnum.open)
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class EvidenceItem(Base):
    __tablename__ = 'evidence_items'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey('projects.id', ondelete='CASCADE'), index=True)
    audit_run_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('audit_runs.id', ondelete='SET NULL'), nullable=True, index=True)
    integration_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('integrations.id', ondelete='SET NULL'), nullable=True)
    item_type: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class RemediationTask(Base):
    __tablename__ = 'remediation_tasks'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey('projects.id', ondelete='CASCADE'), index=True)
    audit_run_id: Mapped[str] = mapped_column(String(36), ForeignKey('audit_runs.id', ondelete='CASCADE'), index=True)
    finding_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('findings.id', ondelete='SET NULL'), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default='')
    status: Mapped[str] = mapped_column(String(32), default='open')
    assignee_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AuditLogEntry(Base):
    __tablename__ = 'audit_log_entries'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey('organizations.id', ondelete='CASCADE'), index=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
