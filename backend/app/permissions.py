from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Project, RoleEnum, RolePermission

DEFAULT_PERMISSIONS: dict[RoleEnum, set[tuple[str, str]]] = {
    RoleEnum.org_admin: {
        ('project', 'read'),
        ('project', 'write'),
        ('project', 'delete'),
        ('audit_run', 'launch'),
        ('evidence', 'upload'),
        ('report', 'export_package'),
        ('finding', 'approve'),
        ('remediation', 'manage'),
        ('secret', 'manage'),
    },
    RoleEnum.auditor: {
        ('project', 'read'),
        ('project', 'write'),
        ('audit_run', 'launch'),
        ('evidence', 'upload'),
        ('report', 'export_package'),
        ('finding', 'approve'),
    },
    RoleEnum.security_reviewer: {
        ('project', 'read'),
        ('finding', 'approve'),
        ('report', 'export_package'),
    },
    RoleEnum.remediation_manager: {
        ('project', 'read'),
        ('remediation', 'manage'),
    },
    RoleEnum.client_viewer: {
        ('project', 'read'),
    },
}


async def _has_custom_permission(
    db: AsyncSession,
    *,
    org_id: str,
    role: RoleEnum,
    resource: str,
    action: str,
) -> bool | None:
    rows = (
        await db.execute(
            select(RolePermission).where(
                RolePermission.role == role,
                RolePermission.resource == resource,
                RolePermission.action == action,
                (RolePermission.org_id == org_id) | RolePermission.org_id.is_(None),
            )
        )
    ).scalars().all()
    if not rows:
        return None
    return True


def _abac_project_denied(project: Project | None, action: str, role: RoleEnum) -> bool:
    if project is None:
        return False
    tags = project.tags_json or {}
    sensitivity = str(tags.get('data_sensitivity', 'internal')).lower()
    if sensitivity == 'restricted' and action in {'delete', 'export_package'} and role != RoleEnum.org_admin:
        return True
    if project.criticality.value == 'high' and action == 'delete' and role not in {RoleEnum.org_admin}:
        return True
    return False


async def require_permission(
    db: AsyncSession,
    *,
    org_id: str,
    role: str,
    resource: str,
    action: str,
    project: Project | None = None,
) -> None:
    role_enum = RoleEnum(role)
    custom = await _has_custom_permission(db, org_id=org_id, role=role_enum, resource=resource, action=action)
    if custom is True:
        if _abac_project_denied(project, action, role_enum):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='ABAC policy denied')
        return

    if (resource, action) not in DEFAULT_PERMISSIONS.get(role_enum, set()):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Permission denied')
    if _abac_project_denied(project, action, role_enum):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='ABAC policy denied')
