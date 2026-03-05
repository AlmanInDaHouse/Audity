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


async def seed() -> None:
    async with SessionLocal() as db:
        existing = await db.scalar(select(Organization).where(Organization.name == 'Demo Org'))
        if existing is not None:
            print('Seed data already present')
            return

        org = Organization(name='Demo Org')
        db.add(org)
        await db.flush()
        await set_current_org(db, org.id)

        admin = User(email='admin@demo.local', display_name='Org Admin')
        auditor = User(email='auditor@demo.local', display_name='Security Auditor')
        viewer = User(email='viewer@demo.local', display_name='Client Viewer')
        db.add_all([admin, auditor, viewer])
        await db.flush()

        db.add_all(
            [
                Membership(org_id=org.id, user_id=admin.id, role=RoleEnum.org_admin),
                Membership(org_id=org.id, user_id=auditor.id, role=RoleEnum.auditor),
                Membership(org_id=org.id, user_id=viewer.id, role=RoleEnum.client_viewer),
            ]
        )
        db.add(OrgSecurityPolicy(org_id=org.id))
        db.add(PricingPlan(org_id=org.id))

        project = Project(
            org_id=org.id,
            name='Demo Project',
            description='Project for MVP validation',
            criticality=CriticalityEnum.high,
        )
        db.add(project)

        checksum = compute_catalog_checksum()
        db.add_all(
            [
                ControlCatalog(
                    org_id=None,
                    name='ISO27001 Annex A',
                    framework='ISO27001',
                    version='v1',
                    checksum=checksum,
                    source_path='/catalogs/iso27001_annex_a.v1.yml',
                    is_global=True,
                ),
                ControlCatalog(
                    org_id=None,
                    name='ENS medidas',
                    framework='ENS',
                    version='v1',
                    checksum=checksum,
                    source_path='/catalogs/ens_measures.v1.yml',
                    is_global=True,
                ),
                ControlCatalog(
                    org_id=None,
                    name='RGPD checklist',
                    framework='RGPD',
                    version='v1',
                    checksum=checksum,
                    source_path='/catalogs/rgpd_checklist.v1.yml',
                    is_global=True,
                ),
            ]
        )

        await db.commit()
        print('Seed complete')
        print(f'Org ID: {org.id}')
        print(f'Project ID: {project.id}')
        print('Users: admin@demo.local / auditor@demo.local / viewer@demo.local')


if __name__ == '__main__':
    import asyncio

    asyncio.run(seed())
