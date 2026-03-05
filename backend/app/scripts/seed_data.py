from __future__ import annotations

from sqlalchemy import select

from app.catalog_engine import compute_catalog_checksum
from app.db import SessionLocal
from app.models import (
    ControlCatalog,
    CriticalityEnum,
    Membership,
    Organization,
    OrgSecurityPolicy,
    PricingPlan,
    Project,
    RoleEnum,
    User,
)
from app.tenancy import set_current_org


async def _get_or_create_user(db, email: str, display_name: str) -> User:
    user = await db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(email=email, display_name=display_name)
        db.add(user)
        await db.flush()
    return user


async def _ensure_membership(db, org_id: str, user_id: str, role: RoleEnum) -> None:
    membership = await db.scalar(select(Membership).where(Membership.org_id == org_id, Membership.user_id == user_id))
    if membership is None:
        db.add(Membership(org_id=org_id, user_id=user_id, role=role))


async def _ensure_global_catalog(db, checksum: str, name: str, framework: str, source_path: str) -> None:
    existing = await db.scalar(
        select(ControlCatalog).where(
            ControlCatalog.org_id.is_(None),
            ControlCatalog.framework == framework,
            ControlCatalog.version == 'v1',
        )
    )
    if existing is None:
        db.add(
            ControlCatalog(
                org_id=None,
                name=name,
                framework=framework,
                version='v1',
                checksum=checksum,
                source_path=source_path,
                is_global=True,
            )
        )


async def seed() -> None:
    async with SessionLocal() as db:
        org = await db.scalar(select(Organization).where(Organization.name == 'Demo Org'))
        if org is None:
            org = Organization(name='Demo Org')
            db.add(org)
            await db.flush()
        await set_current_org(db, org.id)

        admin = await _get_or_create_user(db, email='admin@demo.local', display_name='Org Admin')
        auditor = await _get_or_create_user(db, email='auditor@demo.local', display_name='Security Auditor')
        viewer = await _get_or_create_user(db, email='viewer@demo.local', display_name='Client Viewer')

        await _ensure_membership(db, org_id=org.id, user_id=admin.id, role=RoleEnum.org_admin)
        await _ensure_membership(db, org_id=org.id, user_id=auditor.id, role=RoleEnum.auditor)
        await _ensure_membership(db, org_id=org.id, user_id=viewer.id, role=RoleEnum.client_viewer)

        if await db.get(OrgSecurityPolicy, org.id) is None:
            db.add(OrgSecurityPolicy(org_id=org.id))
        if await db.get(PricingPlan, org.id) is None:
            db.add(PricingPlan(org_id=org.id))

        project = await db.scalar(
            select(Project).where(Project.org_id == org.id, Project.name == 'Demo Project')
        )
        if project is None:
            project = Project(
                org_id=org.id,
                name='Demo Project',
                description='Project for MVP validation',
                criticality=CriticalityEnum.high,
            )
            db.add(project)

        checksum = compute_catalog_checksum()
        await _ensure_global_catalog(
            db,
            checksum,
            name='ISO27001 Annex A',
            framework='ISO27001',
            source_path='/catalogs/iso27001_annex_a.v1.yml',
        )
        await _ensure_global_catalog(
            db,
            checksum,
            name='ENS medidas',
            framework='ENS',
            source_path='/catalogs/ens_measures.v1.yml',
        )
        await _ensure_global_catalog(
            db,
            checksum,
            name='RGPD checklist',
            framework='RGPD',
            source_path='/catalogs/rgpd_checklist.v1.yml',
        )

        await db.commit()
        print('Seed complete (idempotent)')
        print(f'Org ID: {org.id}')
        print(f'Project ID: {project.id}')
        print('Users: admin@demo.local / auditor@demo.local / viewer@demo.local')


if __name__ == '__main__':
    import asyncio

    asyncio.run(seed())
