from __future__ import annotations

import asyncio
import os
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

# why this: tests force deterministic local mode and avoid external dependency flakiness.
os.environ.setdefault('APP_ENV', 'test')
os.environ.setdefault('WORKFLOW_MODE', 'inline')
os.environ.setdefault('STORAGE_BACKEND', 'memory')
os.environ.setdefault('AUTO_CREATE_SCHEMA', 'false')
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///./audity_test.db'

from app.db import Base, SessionLocal, engine
from app.main import app
from app.models import CriticalityEnum, Membership, Organization, Project, RoleEnum, User


@pytest.fixture(scope='session', autouse=True)
def setup_schema() -> None:
    async def _setup() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_setup())


@pytest.fixture(autouse=True)
def clean_db() -> None:
    async def _clean() -> None:
        async with SessionLocal() as db:
            tables = [
                'audit_log_entries',
                'remediation_tasks',
                'findings',
                'audit_runs',
                'evidence_items',
                'integrations',
                'projects',
                'control_catalogs',
                'memberships',
                'users',
                'organizations',
            ]
            for table in tables:
                await db.execute(text(f'DELETE FROM {table}'))
            await db.commit()

    asyncio.run(_clean())


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def seeded_ids() -> dict[str, Any]:
    async def _seed() -> dict[str, Any]:
        async with SessionLocal() as db:
            org = Organization(name='Test Org')
            db.add(org)
            await db.flush()

            admin = User(email='admin@test.local', display_name='Admin')
            auditor = User(email='auditor@test.local', display_name='Auditor')
            viewer = User(email='viewer@test.local', display_name='Viewer')
            db.add_all([admin, auditor, viewer])
            await db.flush()

            db.add_all(
                [
                    Membership(org_id=org.id, user_id=admin.id, role=RoleEnum.org_admin),
                    Membership(org_id=org.id, user_id=auditor.id, role=RoleEnum.auditor),
                    Membership(org_id=org.id, user_id=viewer.id, role=RoleEnum.client_viewer),
                ]
            )

            project = Project(
                org_id=org.id,
                name='Main Project',
                description='Seed project',
                criticality=CriticalityEnum.high,
            )
            db.add(project)
            await db.commit()

            return {
                'org_id': org.id,
                'project_id': project.id,
                'users': {
                    'admin': admin.email,
                    'auditor': auditor.email,
                    'viewer': viewer.email,
                },
            }

    return asyncio.run(_seed())


def login(client: TestClient, email: str, org_id: str) -> str:
    response = client.post('/auth/mock/login', json={'email': email, 'org_id': org_id})
    assert response.status_code == 200, response.text
    return response.json()['access_token']
