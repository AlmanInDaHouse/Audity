from __future__ import annotations

import json

from app import main as main_module
from app.db import SessionLocal
from app.models import Integration
from app.temporal_workflow import AuditRunWorkflowInput
from app.workflow_runtime import AuditWorkflowInput, execute_inline


def _login(client, email: str, org_id: str, *, mfa: bool = False) -> dict:
    res = client.post('/auth/mock/login', json={'email': email, 'org_id': org_id, 'mfa': mfa})
    assert res.status_code == 200, res.text
    return res.json()


def test_refresh_rotation_and_logout(client, seeded_ids):
    session = _login(client, seeded_ids['users']['admin'], seeded_ids['org_id'], mfa=True)
    refresh = session['refresh_token']
    refresh_res = client.post('/auth/refresh', json={'refresh_token': refresh, 'mfa': True})
    assert refresh_res.status_code == 200, refresh_res.text
    rotated = refresh_res.json()
    assert rotated['refresh_token'] != refresh

    logout = client.post('/auth/logout', json={'refresh_token': rotated['refresh_token']})
    assert logout.status_code == 200
    assert logout.json()['revoked'] is True

    revoked_refresh = client.post('/auth/refresh', json={'refresh_token': rotated['refresh_token'], 'mfa': True})
    assert revoked_refresh.status_code == 401


def test_secret_store_and_no_plaintext_integration_config(client, seeded_ids):
    admin = _login(client, seeded_ids['users']['admin'], seeded_ids['org_id'])['access_token']
    headers = {'Authorization': f'Bearer {admin}'}

    create_secret = client.post(
        f"/organizations/{seeded_ids['org_id']}/secrets",
        json={'name': 'github_token', 'value': 'ghp_super_secret_token'},
        headers=headers,
    )
    assert create_secret.status_code == 200, create_secret.text
    secret_ref = create_secret.json()['secret_ref']

    invalid = client.post(
        f"/projects/{seeded_ids['project_id']}/integrations",
        json={
            'provider': 'github',
            'name': 'invalid',
            'config_json': {'token': 'plaintext-should-fail'},
            'secret_ref': None,
            'is_enabled': True,
        },
        headers=headers,
    )
    assert invalid.status_code == 400

    valid = client.post(
        f"/projects/{seeded_ids['project_id']}/integrations",
        json={
            'provider': 'github',
            'name': 'valid',
            'config_json': {'repos': ['acme/audity']},
            'secret_ref': secret_ref,
            'is_enabled': True,
        },
        headers=headers,
    )
    assert valid.status_code == 200, valid.text
    integration_id = valid.json()['id']

    async def _assert_db() -> None:
        async with SessionLocal() as db:
            row = await db.get(Integration, integration_id)
            assert row is not None
            assert row.secret_ref == secret_ref
            assert 'ghp_super_secret_token' not in json.dumps(row.config_json)

    import asyncio

    asyncio.run(_assert_db())


def test_scim_create_patch_user_and_group_mapping(client, seeded_ids):
    admin = _login(client, seeded_ids['users']['admin'], seeded_ids['org_id'])['access_token']
    headers = {'Authorization': f'Bearer {admin}'}
    token_resp = client.post(
        f"/organizations/{seeded_ids['org_id']}/scim/tokens",
        json={'token_name': 'scim_token', 'token_value': 'super-long-scim-token-value', 'description': 'tests'},
        headers=headers,
    )
    assert token_resp.status_code == 200, token_resp.text

    scim_headers = {'Authorization': 'Bearer super-long-scim-token-value'}
    create_user = client.post(
        '/scim/v2/Users',
        json={
            'userName': 'scim.user@test.local',
            'displayName': 'SCIM User',
            'active': True,
            'groups': [{'value': 'auditor'}],
        },
        headers=scim_headers,
    )
    assert create_user.status_code == 200, create_user.text
    user_id = create_user.json()['id']

    patch_user = client.patch(
        f'/scim/v2/Users/{user_id}',
        json={
            'Operations': [
                {'op': 'Replace', 'path': 'active', 'value': False},
                {'op': 'Replace', 'path': 'groups', 'value': [{'value': 'security_reviewer'}]},
            ]
        },
        headers=scim_headers,
    )
    assert patch_user.status_code == 200, patch_user.text
    assert patch_user.json()['active'] is False

    groups = client.get('/scim/v2/Groups', headers=scim_headers)
    assert groups.status_code == 200, groups.text
    all_groups = groups.json()['Resources']
    target = next(g for g in all_groups if g['id'] == 'security_reviewer')
    assert any(member['value'] == user_id for member in target['members'])


def test_upload_quarantine_and_signature_verification(client, seeded_ids, monkeypatch):
    token = _login(client, seeded_ids['users']['auditor'], seeded_ids['org_id'])['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    async def _infected(_content: bytes) -> str:
        return 'infected'

    monkeypatch.setattr(main_module, 'scan_upload_activity', _infected)
    upload = client.post(
        f"/projects/{seeded_ids['project_id']}/evidence/upload",
        data={'item_type': 'manual_upload', 'metadata_json': '{}'},
        files={'file': ('infected.txt', b'virus', 'text/plain')},
        headers=headers,
    )
    assert upload.status_code == 200, upload.text
    evidence_id = upload.json()['id']
    assert upload.json()['scan_status'] == 'infected'

    blocked_download = client.get(f'/evidence/{evidence_id}/download', headers=headers)
    assert blocked_download.status_code == 423

    async def _clean(_content: bytes) -> str:
        return 'clean'

    monkeypatch.setattr(main_module, 'scan_upload_activity', _clean)
    clean_upload = client.post(
        f"/projects/{seeded_ids['project_id']}/evidence/upload",
        data={'item_type': 'manual_upload', 'metadata_json': '{}'},
        files={'file': ('clean.txt', b'clean', 'text/plain')},
        headers=headers,
    )
    assert clean_upload.status_code == 200, clean_upload.text
    clean_id = clean_upload.json()['id']

    verify = client.get(f'/evidence/{clean_id}/verify-signature', headers=headers)
    assert verify.status_code == 200
    assert verify.json()['valid'] is True


def test_export_auditor_package_contains_artifacts(client, seeded_ids, monkeypatch):
    async def _launch_inline(payload: AuditRunWorkflowInput) -> None:
        await execute_inline(AuditWorkflowInput(**payload.__dict__))

    monkeypatch.setattr(main_module, 'launch_audit_workflow', _launch_inline)

    auth = _login(client, seeded_ids['users']['auditor'], seeded_ids['org_id'], mfa=True)
    token = auth['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    run = client.post(
        f"/projects/{seeded_ids['project_id']}/audit-runs",
        json={'catalog_version': 'v1'},
        headers=headers,
    )
    assert run.status_code == 200, run.text
    run_id = run.json()['id']

    export = client.post(
        f"/projects/{seeded_ids['project_id']}/audit-runs/{run_id}/export-package",
        headers=headers,
    )
    assert export.status_code == 200, export.text
    assert export.json()['package_id']

    package_evidence_id = export.json()['evidence_id']
    download = client.get(f'/evidence/{package_evidence_id}/download', headers=headers)
    assert download.status_code == 200
    assert download.headers.get('content-type', '').startswith('application/zip')
