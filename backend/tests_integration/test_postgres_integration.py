from __future__ import annotations

import os

import asyncpg
import httpx
import pytest


def _pg_dsn() -> str:
    raw = os.getenv('DATABASE_URL', 'postgresql+asyncpg://audity:audity@postgres:5432/audity')
    return raw.replace('postgresql+asyncpg://', 'postgresql://', 1)


async def _login(client: httpx.AsyncClient, base_url: str, email: str, org_id: str) -> str:
    response = await client.post(
        f'{base_url}/auth/mock/login',
        json={'email': email, 'org_id': org_id},
    )
    assert response.status_code == 200, response.text
    return response.json()['access_token']


@pytest.mark.asyncio
async def test_tenant_isolation_and_rbac_live_api(api_base_url, org_context):
    async with httpx.AsyncClient(timeout=30.0) as client:
        admin_token = await _login(client, api_base_url, org_context['users']['admin_a'], org_context['org_a_id'])
        auditor_token = await _login(client, api_base_url, org_context['users']['auditor_a'], org_context['org_a_id'])
        viewer_token = await _login(client, api_base_url, org_context['users']['viewer_a'], org_context['org_a_id'])

        admin_headers = {'Authorization': f'Bearer {admin_token}'}
        auditor_headers = {'Authorization': f'Bearer {auditor_token}'}
        viewer_headers = {'Authorization': f'Bearer {viewer_token}'}

        # Cross-tenant isolation: org A token cannot read org B project/run/evidence.
        projects_b = await client.get(
            f"{api_base_url}/organizations/{org_context['org_b_id']}/projects", headers=admin_headers
        )
        project_b = await client.get(f"{api_base_url}/projects/{org_context['project_b_id']}", headers=admin_headers)
        run_b = await client.get(
            f"{api_base_url}/projects/{org_context['project_b_id']}/audit-runs/{org_context['run_b_id']}",
            headers=admin_headers,
        )
        evidence_b = await client.get(
            f"{api_base_url}/evidence/{org_context['evidence_b_id']}/download", headers=admin_headers
        )
        assert projects_b.status_code == 403
        assert project_b.status_code == 404
        assert run_b.status_code == 404
        assert evidence_b.status_code == 404

        admin_log = await client.get(f'{api_base_url}/audit-log', headers=admin_headers)
        auditor_run = await client.post(
            f"{api_base_url}/projects/{org_context['project_a_id']}/audit-runs",
            json={'catalog_version': 'v1'},
            headers=auditor_headers,
        )
        auditor_log = await client.get(f'{api_base_url}/audit-log', headers=auditor_headers)
        viewer_run = await client.post(
            f"{api_base_url}/projects/{org_context['project_a_id']}/audit-runs",
            json={'catalog_version': 'v1'},
            headers=viewer_headers,
        )
        viewer_upload = await client.post(
            f"{api_base_url}/projects/{org_context['project_a_id']}/evidence/upload",
            data={'item_type': 'manual_upload', 'metadata_json': '{}'},
            files={'file': ('viewer.txt', b'blocked', 'text/plain')},
            headers=viewer_headers,
        )
        assert admin_log.status_code == 200
        assert auditor_run.status_code == 200
        assert auditor_log.status_code == 403
        assert viewer_run.status_code == 403
        assert viewer_upload.status_code == 403


@pytest.mark.asyncio
async def test_audit_log_append_only_and_hash_chain_in_postgres(api_base_url, org_context):
    async with httpx.AsyncClient(timeout=30.0) as client:
        admin_token = await _login(client, api_base_url, org_context['users']['admin_a'], org_context['org_a_id'])
        create_project = await client.post(
            f"{api_base_url}/organizations/{org_context['org_a_id']}/projects",
            json={'name': 'append-only proof', 'description': '', 'criticality': 'medium'},
            headers={'Authorization': f'Bearer {admin_token}'},
        )
        assert create_project.status_code == 200

    conn = await asyncpg.connect(_pg_dsn())
    try:
        trigger_name = await conn.fetchval(
            """
            SELECT tgname
            FROM pg_trigger
            WHERE tgrelid = 'audit_log_entries'::regclass
              AND NOT tgisinternal
              AND tgname = 'trg_audit_log_no_update'
            """
        )
        assert trigger_name == 'trg_audit_log_no_update'

        latest_id = await conn.fetchval(
            """
            SELECT id
            FROM audit_log_entries
            WHERE org_id = $1
            ORDER BY id DESC
            LIMIT 1
            """,
            org_context['org_a_id'],
        )
        assert latest_id is not None

        with pytest.raises(asyncpg.PostgresError):
            await conn.execute("UPDATE audit_log_entries SET action='tamper' WHERE id=$1", latest_id)

        with pytest.raises(asyncpg.PostgresError):
            await conn.execute('DELETE FROM audit_log_entries WHERE id=$1', latest_id)

        chain_breaks = await conn.fetchval(
            """
            WITH ordered AS (
                SELECT org_id,id,prev_hash,entry_hash,
                       lag(entry_hash) OVER (PARTITION BY org_id ORDER BY id) AS expected_prev
                FROM audit_log_entries
            )
            SELECT count(*) FROM ordered
            WHERE prev_hash <> COALESCE(expected_prev, repeat('0',64))
            """
        )
        assert chain_breaks == 0
    finally:
        await conn.close()
