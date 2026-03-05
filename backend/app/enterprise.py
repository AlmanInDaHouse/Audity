from __future__ import annotations

import json
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit_log import append_audit_log
from app.auth_sessions import revoke_session, rotate_session
from app.config import get_settings
from app.deps import UserContext, get_current_user, require_mfa, require_roles
from app.models import (
    AuditPackage,
    AuditRun,
    EvidenceItem,
    Finding,
    FindingApproval,
    Membership,
    OrgSecurityPolicy,
    OutboundIntegration,
    PricingPlan,
    Project,
    RemediationComment,
    RemediationTask,
    RoleEnum,
    RolePermission,
    ScimAccessToken,
    User,
    Waiver,
)
from app.package_export import build_auditor_package
from app.permissions import require_permission
from app.secret_store import SecretStoreError, get_secret_store
from app.security import get_signer
from app.signing import verify_bundle
from app.storage import get_object_store

router = APIRouter()


class SecretSetRequest(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    value: str = Field(min_length=1, max_length=8192)


class SecretRotateRequest(BaseModel):
    secret_ref: str
    value: str = Field(min_length=1, max_length=8192)


class SecretValidateRequest(BaseModel):
    secret_ref: str


class SessionRefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=512)
    mfa: bool = False


class SessionLogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=512)


class ScimTokenCreate(BaseModel):
    token_name: str = Field(min_length=2, max_length=128)
    token_value: str = Field(min_length=10, max_length=4096)
    description: str = Field(default='SCIM token', max_length=255)


class RolePermissionCreate(BaseModel):
    role: RoleEnum
    resource: str = Field(min_length=2, max_length=64)
    action: str = Field(min_length=2, max_length=64)
    conditions_json: dict[str, Any] = Field(default_factory=dict)


class PolicyUpdateRequest(BaseModel):
    require_mfa_sensitive: bool = False
    max_upload_bytes: int = Field(default=20 * 1024 * 1024, ge=1024 * 1024, le=1024 * 1024 * 1024)
    retention_days: int = Field(default=365, ge=1, le=3650)


class ApprovalDecisionRequest(BaseModel):
    status: str = Field(pattern='^(approved|rejected)$')
    notes: str = ''


class WaiverCreateRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=4000)
    expires_at: datetime


class CommentCreateRequest(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class PricingPlanRequest(BaseModel):
    plan_code: str = Field(min_length=2, max_length=64)
    max_assets: int = Field(ge=1, le=1_000_000)
    max_upload_bytes: int = Field(ge=1024 * 1024, le=1024 * 1024 * 1024)
    modules_json: dict[str, bool] = Field(default_factory=dict)


class OutboundIntegrationCreate(BaseModel):
    kind: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=2, max_length=255)
    config_json: dict[str, Any] = Field(default_factory=dict)
    secret_ref: str | None = None
    is_enabled: bool = True


@router.get('/enterprise/features')
async def enterprise_features() -> dict[str, Any]:
    settings = get_settings()
    return {
        'enterprise_features_enabled': settings.enterprise_features_enabled,
        'feature_auth_enterprise': settings.feature_auth_enterprise,
        'feature_scim': settings.feature_scim,
        'feature_secret_store': settings.feature_secret_store,
        'feature_upload_av_scan': settings.feature_upload_av_scan,
        'feature_signing': settings.feature_signing,
        'feature_rbac_abac': settings.feature_rbac_abac,
        'feature_approvals': settings.feature_approvals,
        'feature_reporting_package': settings.feature_reporting_package,
        'feature_pricing': settings.feature_pricing,
    }


# why this: this indirection keeps mypy/ruff happy while avoiding circular imports from local function binding.
from app.db import get_db as _get_db  # noqa: E402


@router.post('/auth/refresh')
async def auth_refresh_real(payload: SessionRefreshRequest, db: AsyncSession = Depends(_get_db)) -> dict[str, Any]:
    try:
        session, new_refresh_token, user, membership = await rotate_session(db, refresh_token=payload.refresh_token)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    access_token = get_signer().token(
        sub=user.id,
        email=user.email,
        org_id=session.org_id,
        role=membership.role.value,
        sid=session.id,
        mfa=payload.mfa,
    )
    await db.commit()
    return {
        'access_token': access_token,
        'refresh_token': new_refresh_token,
        'token_type': 'bearer',
        'expires_in': get_settings().access_token_ttl_minutes * 60,
    }


@router.post('/auth/logout')
async def auth_logout(payload: SessionLogoutRequest, db: AsyncSession = Depends(_get_db)) -> dict[str, bool]:
    revoked = await revoke_session(db, refresh_token=payload.refresh_token)
    await db.commit()
    return {'revoked': revoked}


@router.post('/organizations/{org_id}/secrets')
async def set_secret(
    org_id: str,
    payload: SecretSetRequest,
    ctx: UserContext = Depends(require_roles('org_admin')),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    store = get_secret_store()
    secret_ref = await store.set(org_id, payload.name, payload.value)
    return {'secret_ref': secret_ref}


@router.post('/organizations/{org_id}/secrets/rotate')
async def rotate_secret(
    org_id: str,
    payload: SecretRotateRequest,
    ctx: UserContext = Depends(require_roles('org_admin')),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    store = get_secret_store()
    new_ref = await store.rotate(payload.secret_ref, payload.value)
    return {'secret_ref': new_ref}


@router.post('/organizations/{org_id}/secrets/validate')
async def validate_secret(
    org_id: str,
    payload: SecretValidateRequest,
    ctx: UserContext = Depends(require_roles('org_admin')),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    store = get_secret_store()
    try:
        value = await store.get(payload.secret_ref)
    except SecretStoreError as exc:
        return {'valid': False, 'error': str(exc)}
    return {'valid': True, 'length': len(value)}


@router.put('/organizations/{org_id}/security-policy')
async def upsert_security_policy(
    org_id: str,
    payload: PolicyUpdateRequest,
    ctx: UserContext = Depends(require_roles('org_admin')),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    policy = await db.get(OrgSecurityPolicy, org_id)
    if policy is None:
        policy = OrgSecurityPolicy(org_id=org_id)
        db.add(policy)
    policy.require_mfa_sensitive = payload.require_mfa_sensitive
    policy.max_upload_bytes = payload.max_upload_bytes
    policy.retention_days = payload.retention_days
    await db.commit()
    return {
        'org_id': org_id,
        'require_mfa_sensitive': policy.require_mfa_sensitive,
        'max_upload_bytes': policy.max_upload_bytes,
        'retention_days': policy.retention_days,
    }


@router.get('/organizations/{org_id}/security-policy')
async def get_security_policy(
    org_id: str,
    ctx: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    policy = await db.get(OrgSecurityPolicy, org_id)
    if policy is None:
        return {
            'org_id': org_id,
            'require_mfa_sensitive': False,
            'max_upload_bytes': 20 * 1024 * 1024,
            'retention_days': 365,
        }
    return {
        'org_id': org_id,
        'require_mfa_sensitive': policy.require_mfa_sensitive,
        'max_upload_bytes': policy.max_upload_bytes,
        'retention_days': policy.retention_days,
    }


@router.post('/organizations/{org_id}/scim/tokens')
async def create_scim_token(
    org_id: str,
    payload: ScimTokenCreate,
    ctx: UserContext = Depends(require_roles('org_admin')),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    store = get_secret_store()
    secret_ref = await store.set(org_id, payload.token_name, payload.token_value)
    token = ScimAccessToken(org_id=org_id, token_secret_ref=secret_ref, description=payload.description, is_enabled=True)
    db.add(token)
    await db.commit()
    return {'id': token.id, 'token_secret_ref': secret_ref}


async def _resolve_scim_org(request: Request, db: AsyncSession) -> str:
    auth = request.headers.get('authorization', '')
    if not auth.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='SCIM bearer token required')
    raw_token = auth.split(' ', 1)[1]
    rows = (await db.execute(select(ScimAccessToken).where(ScimAccessToken.is_enabled.is_(True)))).scalars().all()
    store = get_secret_store()
    for row in rows:
        try:
            expected = await store.get(row.token_secret_ref)
        except SecretStoreError:
            continue
        if secrets.compare_digest(expected, raw_token):
            return row.org_id
    raise HTTPException(status_code=401, detail='Invalid SCIM token')


def _role_from_group_name(name: str) -> RoleEnum:
    normalized = name.strip().lower()
    mapping = {
        'org_admin': RoleEnum.org_admin,
        'auditor': RoleEnum.auditor,
        'client_viewer': RoleEnum.client_viewer,
        'security_reviewer': RoleEnum.security_reviewer,
        'remediation_manager': RoleEnum.remediation_manager,
    }
    if normalized not in mapping:
        raise HTTPException(status_code=400, detail=f'Unsupported SCIM group/role: {name}')
    return mapping[normalized]


@router.get('/scim/v2/Users')
async def scim_list_users(request: Request, db: AsyncSession = Depends(_get_db)) -> dict[str, Any]:
    org_id = await _resolve_scim_org(request, db)
    rows = (
        await db.execute(
            select(User, Membership.role)
            .join(Membership, Membership.user_id == User.id)
            .where(Membership.org_id == org_id)
        )
    ).all()
    resources = []
    for user, role in rows:
        resources.append(
            {
                'id': user.id,
                'userName': user.email,
                'active': user.is_active,
                'displayName': user.display_name,
                'groups': [{'value': role.value}],
            }
        )
    return {'schemas': ['urn:ietf:params:scim:api:messages:2.0:ListResponse'], 'Resources': resources}


@router.post('/scim/v2/Users')
async def scim_create_user(request: Request, payload: dict[str, Any], db: AsyncSession = Depends(_get_db)) -> dict[str, Any]:
    org_id = await _resolve_scim_org(request, db)
    email = str(payload.get('userName') or '').strip().lower()
    display_name = str(payload.get('displayName') or email or 'SCIM User').strip()
    if not email:
        raise HTTPException(status_code=400, detail='userName is required')
    active = bool(payload.get('active', True))
    group_values = [g.get('value') for g in payload.get('groups', []) if isinstance(g, dict)]
    role = _role_from_group_name(group_values[0]) if group_values else RoleEnum.client_viewer

    user = await db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(email=email, display_name=display_name, is_active=active)
        db.add(user)
        await db.flush()
    else:
        user.display_name = display_name
        user.is_active = active

    membership = await db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.org_id == org_id))
    if membership is None:
        membership = Membership(org_id=org_id, user_id=user.id, role=role)
        db.add(membership)
    else:
        membership.role = role

    await append_audit_log(
        db,
        org_id=org_id,
        actor_user_id=None,
        action='scim.user.upsert',
        entity_type='user',
        entity_id=user.id,
        payload={'email': email, 'role': role.value, 'active': active},
    )
    await db.commit()
    return {'id': user.id, 'userName': user.email, 'active': user.is_active, 'displayName': user.display_name}


@router.patch('/scim/v2/Users/{user_id}')
async def scim_patch_user(
    user_id: str,
    request: Request,
    payload: dict[str, Any],
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    org_id = await _resolve_scim_org(request, db)
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail='User not found')
    membership = await db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.org_id == org_id))
    if membership is None:
        raise HTTPException(status_code=404, detail='Membership not found')

    operations = payload.get('Operations', [])
    for op in operations:
        path = str(op.get('path', '')).lower()
        value = op.get('value')
        if path in {'active', 'urn:ietf:params:scim:schemas:core:2.0:user:active'}:
            user.is_active = bool(value)
        elif path in {'displayname', 'urn:ietf:params:scim:schemas:core:2.0:user:displayname'}:
            user.display_name = str(value)
        elif path == 'groups':
            if isinstance(value, list) and value:
                membership.role = _role_from_group_name(str(value[0].get('value', 'client_viewer')))

    await append_audit_log(
        db,
        org_id=org_id,
        actor_user_id=None,
        action='scim.user.patch',
        entity_type='user',
        entity_id=user.id,
        payload={'operations': operations},
    )
    await db.commit()
    return {'id': user.id, 'active': user.is_active, 'displayName': user.display_name}


@router.get('/scim/v2/Groups')
async def scim_list_groups(request: Request, db: AsyncSession = Depends(_get_db)) -> dict[str, Any]:
    org_id = await _resolve_scim_org(request, db)
    resources: list[dict[str, Any]] = []
    for role in RoleEnum:
        members = (
            await db.execute(select(Membership.user_id).where(Membership.org_id == org_id, Membership.role == role))
        ).scalars().all()
        resources.append(
            {
                'id': role.value,
                'displayName': role.value,
                'members': [{'value': member_id} for member_id in members],
            }
        )
    return {'schemas': ['urn:ietf:params:scim:api:messages:2.0:ListResponse'], 'Resources': resources}


@router.patch('/scim/v2/Groups/{group_id}')
async def scim_patch_group(
    group_id: str,
    request: Request,
    payload: dict[str, Any],
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    org_id = await _resolve_scim_org(request, db)
    role = _role_from_group_name(group_id)
    operations = payload.get('Operations', [])
    for op in operations:
        if str(op.get('op', '')).lower() == 'replace' and str(op.get('path', '')).lower() == 'members':
            members = op.get('value', [])
            for member in members:
                user_id = str(member.get('value'))
                membership = await db.scalar(select(Membership).where(Membership.org_id == org_id, Membership.user_id == user_id))
                if membership:
                    membership.role = role
    await db.commit()
    return {'id': role.value, 'displayName': role.value}


@router.get('/organizations/{org_id}/permissions')
async def list_permissions(
    org_id: str,
    ctx: UserContext = Depends(require_roles('org_admin')),
    db: AsyncSession = Depends(_get_db),
) -> list[dict[str, Any]]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    rows = (
        await db.execute(select(RolePermission).where((RolePermission.org_id == org_id) | RolePermission.org_id.is_(None)))
    ).scalars().all()
    return [
        {
            'id': row.id,
            'org_id': row.org_id,
            'role': row.role.value,
            'resource': row.resource,
            'action': row.action,
            'conditions_json': row.conditions_json,
        }
        for row in rows
    ]


@router.post('/organizations/{org_id}/permissions')
async def create_permission(
    org_id: str,
    payload: RolePermissionCreate,
    ctx: UserContext = Depends(require_roles('org_admin')),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    perm = RolePermission(
        org_id=org_id,
        role=payload.role,
        resource=payload.resource,
        action=payload.action,
        conditions_json=payload.conditions_json,
    )
    db.add(perm)
    await db.commit()
    return {'id': perm.id}


@router.post('/findings/{finding_id}/approvals/request')
async def request_finding_approval(
    finding_id: str,
    payload: dict[str, Any],
    ctx: UserContext = Depends(require_mfa),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    finding = await db.scalar(select(Finding).where(Finding.id == finding_id, Finding.org_id == ctx.org_id))
    if finding is None:
        raise HTTPException(status_code=404, detail='Finding not found')
    await require_permission(db, org_id=ctx.org_id, role=ctx.role, resource='finding', action='approve')
    approval = FindingApproval(
        org_id=ctx.org_id,
        finding_id=finding.id,
        requested_by_user_id=ctx.user_id,
        status='pending',
        notes=str(payload.get('notes', '')),
    )
    db.add(approval)
    await db.commit()
    return {'id': approval.id, 'status': approval.status}


@router.post('/finding-approvals/{approval_id}/decision')
async def decide_finding_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    ctx: UserContext = Depends(require_mfa),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    approval = await db.scalar(select(FindingApproval).where(FindingApproval.id == approval_id, FindingApproval.org_id == ctx.org_id))
    if approval is None:
        raise HTTPException(status_code=404, detail='Approval not found')
    await require_permission(db, org_id=ctx.org_id, role=ctx.role, resource='finding', action='approve')
    approval.status = payload.status
    approval.notes = payload.notes
    approval.approved_by_user_id = ctx.user_id
    if payload.status == 'approved':
        finding = await db.get(Finding, approval.finding_id)
        if finding:
            finding.status = 'accepted'
    await db.commit()
    return {'id': approval.id, 'status': approval.status}


@router.post('/findings/{finding_id}/waivers')
async def create_waiver(
    finding_id: str,
    payload: WaiverCreateRequest,
    ctx: UserContext = Depends(require_mfa),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    finding = await db.scalar(select(Finding).where(Finding.id == finding_id, Finding.org_id == ctx.org_id))
    if finding is None:
        raise HTTPException(status_code=404, detail='Finding not found')
    waiver = Waiver(
        org_id=ctx.org_id,
        finding_id=finding.id,
        created_by_user_id=ctx.user_id,
        reason=payload.reason,
        expires_at=payload.expires_at,
    )
    db.add(waiver)
    finding.status = 'accepted'
    await db.commit()
    return {'id': waiver.id, 'expires_at': waiver.expires_at.isoformat()}


@router.post('/remediation-tasks/{task_id}/comments')
async def add_remediation_comment(
    task_id: str,
    payload: CommentCreateRequest,
    ctx: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    task = await db.scalar(select(RemediationTask).where(RemediationTask.id == task_id, RemediationTask.org_id == ctx.org_id))
    if task is None:
        raise HTTPException(status_code=404, detail='Task not found')
    await require_permission(db, org_id=ctx.org_id, role=ctx.role, resource='remediation', action='manage')
    comment = RemediationComment(org_id=ctx.org_id, remediation_task_id=task.id, author_user_id=ctx.user_id, body=payload.body)
    db.add(comment)
    await db.commit()
    return {'id': comment.id, 'body': comment.body}


@router.get('/remediation-tasks/{task_id}/comments')
async def list_remediation_comments(
    task_id: str,
    ctx: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(_get_db),
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(RemediationComment).where(
                RemediationComment.remediation_task_id == task_id,
                RemediationComment.org_id == ctx.org_id,
            )
        )
    ).scalars().all()
    return [
        {
            'id': row.id,
            'body': row.body,
            'author_user_id': row.author_user_id,
            'created_at': row.created_at.isoformat(),
        }
        for row in rows
    ]


@router.post('/projects/{project_id}/audit-runs/{run_id}/export-package')
async def export_auditor_package(
    project_id: str,
    run_id: str,
    ctx: UserContext = Depends(require_mfa),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    await require_permission(db, org_id=ctx.org_id, role=ctx.role, resource='report', action='export_package')
    run = await db.scalar(select(AuditRun).where(AuditRun.id == run_id, AuditRun.project_id == project_id, AuditRun.org_id == ctx.org_id))
    if run is None:
        raise HTTPException(status_code=404, detail='Run not found')
    project = await db.scalar(select(Project).where(Project.id == project_id, Project.org_id == ctx.org_id))
    if project is None:
        raise HTTPException(status_code=404, detail='Project not found')
    findings = (await db.execute(select(Finding).where(Finding.audit_run_id == run.id, Finding.org_id == ctx.org_id))).scalars().all()
    tasks = (
        await db.execute(select(RemediationTask).where(RemediationTask.audit_run_id == run.id, RemediationTask.org_id == ctx.org_id))
    ).scalars().all()
    evidence_items = (
        await db.execute(select(EvidenceItem).where(EvidenceItem.audit_run_id == run.id, EvidenceItem.org_id == ctx.org_id))
    ).scalars().all()

    package_bytes = await build_auditor_package(
        org_id=ctx.org_id,
        project=project,
        run=run,
        findings=findings,
        tasks=tasks,
        evidence_items=evidence_items,
    )

    key = f'packages/{ctx.org_id}/{project_id}/{run_id}/{uuid.uuid4()}.zip'
    stored = await get_object_store().put_bytes(key, package_bytes, 'application/zip')
    evidence = EvidenceItem(
        org_id=ctx.org_id,
        project_id=project_id,
        audit_run_id=run_id,
        integration_id=None,
        item_type='audit_package',
        name=f'auditor-package-{run_id}.zip',
        object_key=stored.key,
        sha256=stored.sha256,
        metadata_json={'content_type': 'application/zip', 'generated_at': datetime.now(UTC).isoformat()},
        created_by_user_id=ctx.user_id,
    )
    db.add(evidence)
    await db.flush()
    pkg = AuditPackage(
        org_id=ctx.org_id,
        project_id=project_id,
        audit_run_id=run_id,
        evidence_id=evidence.id,
        status='ready',
        created_by_user_id=ctx.user_id,
    )
    db.add(pkg)
    await db.commit()
    return {'package_id': pkg.id, 'evidence_id': evidence.id, 'sha256': evidence.sha256}


@router.get('/evidence/{evidence_id}/verify-signature')
async def verify_evidence_signature(
    evidence_id: str,
    ctx: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    evidence = await db.scalar(select(EvidenceItem).where(EvidenceItem.id == evidence_id, EvidenceItem.org_id == ctx.org_id))
    if evidence is None:
        raise HTTPException(status_code=404, detail='Evidence not found')
    valid = verify_bundle(evidence.signature_bundle_json or {})
    return {'evidence_id': evidence.id, 'valid': valid, 'scan_status': evidence.scan_status}


@router.put('/organizations/{org_id}/pricing-plan')
async def upsert_pricing_plan(
    org_id: str,
    payload: PricingPlanRequest,
    ctx: UserContext = Depends(require_roles('org_admin')),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    plan = await db.get(PricingPlan, org_id)
    if plan is None:
        plan = PricingPlan(org_id=org_id)
        db.add(plan)
    plan.plan_code = payload.plan_code
    plan.max_assets = payload.max_assets
    plan.max_upload_bytes = payload.max_upload_bytes
    plan.modules_json = payload.modules_json
    await db.commit()
    return {
        'org_id': org_id,
        'plan_code': plan.plan_code,
        'max_assets': plan.max_assets,
        'max_upload_bytes': plan.max_upload_bytes,
        'modules_json': plan.modules_json,
    }


@router.get('/organizations/{org_id}/pricing-plan')
async def get_pricing_plan(
    org_id: str,
    ctx: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    plan = await db.get(PricingPlan, org_id)
    if plan is None:
        return {
            'org_id': org_id,
            'plan_code': 'starter',
            'max_assets': 50,
            'max_upload_bytes': 20 * 1024 * 1024,
            'modules_json': {},
        }
    return {
        'org_id': org_id,
        'plan_code': plan.plan_code,
        'max_assets': plan.max_assets,
        'max_upload_bytes': plan.max_upload_bytes,
        'modules_json': plan.modules_json,
    }


@router.get('/organizations/{org_id}/outbound-integrations')
async def list_outbound_integrations(
    org_id: str,
    ctx: UserContext = Depends(get_current_user),
    db: AsyncSession = Depends(_get_db),
) -> list[dict[str, Any]]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    rows = (await db.execute(select(OutboundIntegration).where(OutboundIntegration.org_id == org_id))).scalars().all()
    return [
        {
            'id': row.id,
            'kind': row.kind,
            'name': row.name,
            'config_json': row.config_json,
            'secret_ref': row.secret_ref,
            'is_enabled': row.is_enabled,
        }
        for row in rows
    ]


@router.post('/organizations/{org_id}/outbound-integrations')
async def create_outbound_integration(
    org_id: str,
    payload: OutboundIntegrationCreate,
    ctx: UserContext = Depends(require_roles('org_admin')),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    row = OutboundIntegration(
        org_id=org_id,
        kind=payload.kind,
        name=payload.name,
        config_json=payload.config_json,
        secret_ref=payload.secret_ref,
        is_enabled=payload.is_enabled,
    )
    db.add(row)
    await db.commit()
    return {'id': row.id}


@router.post('/organizations/{org_id}/outbound-integrations/{integration_id}/emit')
async def emit_outbound_event(
    org_id: str,
    integration_id: str,
    payload: dict[str, Any],
    ctx: UserContext = Depends(require_roles('org_admin', 'auditor')),
    db: AsyncSession = Depends(_get_db),
) -> dict[str, Any]:
    if org_id != ctx.org_id:
        raise HTTPException(status_code=403, detail='Cross-tenant access denied')
    row = await db.scalar(
        select(OutboundIntegration).where(OutboundIntegration.id == integration_id, OutboundIntegration.org_id == org_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail='Outbound integration not found')
    # why this: enterprise connectors run in async workers in production; API endpoint keeps vendor-neutral contract in MVP.
    return {'delivered': row.is_enabled, 'kind': row.kind, 'payload_size': len(json.dumps(payload))}
