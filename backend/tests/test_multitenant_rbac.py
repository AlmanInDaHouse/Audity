from __future__ import annotations

import asyncio

from app import main as main_module
from app.db import SessionLocal
from app.models import (
    AuditRun,
    AuditStatusEnum,
    CriticalityEnum,
    EvidenceItem,
    Membership,
    Organization,
    Project,
    RoleEnum,
    User,
)


def _login(client, email: str, org_id: str) -> str:
    res = client.post('/auth/mock/login', json={'email': email, 'org_id': org_id})
    assert res.status_code == 200, res.text
    return res.json()['access_token']


def test_multitenant_isolation_blocks_cross_org_reads(client):
    seeded = asyncio.run(_seed_two_orgs())
    token_a = _login(client, seeded['user_a_email'], seeded['org_a_id'])
    headers_a = {'Authorization': f'Bearer {token_a}'}

    list_projects = client.get(f"/organizations/{seeded['org_b_id']}/projects", headers=headers_a)
    assert list_projects.status_code == 403

    get_project = client.get(f"/projects/{seeded['project_b_id']}", headers=headers_a)
    assert get_project.status_code == 404

    get_run = client.get(
        f"/projects/{seeded['project_b_id']}/audit-runs/{seeded['run_b_id']}",
        headers=headers_a,
    )
    assert get_run.status_code == 404

    get_evidence = client.get(f"/evidence/{seeded['evidence_b_id']}/download", headers=headers_a)
    assert get_evidence.status_code == 404


def test_rbac_org_admin_can_read_audit_log(client, seeded_ids):
    token = _login(client, seeded_ids['users']['admin'], seeded_ids['org_id'])
    headers = {'Authorization': f'Bearer {token}'}

    create_project = client.post(
        f"/organizations/{seeded_ids['org_id']}/projects",
        json={'name': 'Log visible', 'description': '', 'criticality': 'medium'},
        headers=headers,
    )
    assert create_project.status_code == 200

    audit_log = client.get('/audit-log', headers=headers)
    assert audit_log.status_code == 200
    assert audit_log.json()['items']


def test_rbac_auditor_can_launch_run_but_not_read_audit_log(client, seeded_ids, monkeypatch):
    async def _noop_launch(_payload) -> None:
        return None

    monkeypatch.setattr(main_module, 'launch_audit_workflow', _noop_launch)
    token = _login(client, seeded_ids['users']['auditor'], seeded_ids['org_id'])
    headers = {'Authorization': f'Bearer {token}'}

    launch = client.post(
        f"/projects/{seeded_ids['project_id']}/audit-runs",
        json={'catalog_version': 'v1'},
        headers=headers,
    )
    assert launch.status_code == 200

    audit_log = client.get('/audit-log', headers=headers)
    assert audit_log.status_code == 403


def test_rbac_client_viewer_cannot_launch_run_or_upload_evidence(client, seeded_ids):
    token = _login(client, seeded_ids['users']['viewer'], seeded_ids['org_id'])
    headers = {'Authorization': f'Bearer {token}'}

    launch = client.post(
        f"/projects/{seeded_ids['project_id']}/audit-runs",
        json={'catalog_version': 'v1'},
        headers=headers,
    )
    assert launch.status_code == 403

    upload = client.post(
        f"/projects/{seeded_ids['project_id']}/evidence/upload",
        data={'item_type': 'manual_upload', 'metadata_json': '{}'},
        files={'file': ('viewer.txt', b'blocked', 'text/plain')},
        headers=headers,
    )
    assert upload.status_code == 403


async def _seed_two_orgs() -> dict[str, str]:
    async with SessionLocal() as db:
        org_a = Organization(name='Org A')
        org_b = Organization(name='Org B')
        db.add_all([org_a, org_b])
        await db.flush()

        user_a = User(email='orga.admin@test.local', display_name='Org A Admin')
        user_b = User(email='orgb.admin@test.local', display_name='Org B Admin')
        db.add_all([user_a, user_b])
        await db.flush()

        db.add_all(
            [
                Membership(org_id=org_a.id, user_id=user_a.id, role=RoleEnum.org_admin),
                Membership(org_id=org_b.id, user_id=user_b.id, role=RoleEnum.org_admin),
            ]
        )

        project_a = Project(
            org_id=org_a.id,
            name='Project A',
            description='Tenant A',
            criticality=CriticalityEnum.medium,
        )
        project_b = Project(
            org_id=org_b.id,
            name='Project B',
            description='Tenant B',
            criticality=CriticalityEnum.high,
        )
        db.add_all([project_a, project_b])
        await db.flush()

        run_b = AuditRun(
            org_id=org_b.id,
            project_id=project_b.id,
            triggered_by_user_id=user_b.id,
            status=AuditStatusEnum.completed,
            catalog_version='v1',
            progress_json={'stage': 'completed'},
            summary_json={},
        )
        db.add(run_b)
        await db.flush()

        evidence_b = EvidenceItem(
            org_id=org_b.id,
            project_id=project_b.id,
            audit_run_id=run_b.id,
            integration_id=None,
            item_type='report',
            name='tenant-b-report.pdf',
            object_key='reports/org-b/project-b/run-b.pdf',
            sha256='0' * 64,
            metadata_json={'content_type': 'application/pdf'},
            created_by_user_id=user_b.id,
        )
        db.add(evidence_b)
        await db.commit()

        return {
            'org_a_id': org_a.id,
            'org_b_id': org_b.id,
            'project_a_id': project_a.id,
            'project_b_id': project_b.id,
            'run_b_id': run_b.id,
            'evidence_b_id': evidence_b.id,
            'user_a_email': user_a.email,
            'user_b_email': user_b.email,
        }
