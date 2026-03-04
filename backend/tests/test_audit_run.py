from __future__ import annotations

from app import main as main_module
from app.temporal_workflow import AuditRunWorkflowInput
from app.workflow_runtime import AuditWorkflowInput, execute_inline


def _login(client, email, org_id):
    res = client.post('/auth/mock/login', json={'email': email, 'org_id': org_id})
    assert res.status_code == 200
    return res.json()['access_token']


def test_create_audit_run_happy_path(client, seeded_ids, monkeypatch):
    async def _launch_inline(payload: AuditRunWorkflowInput) -> None:
        await execute_inline(AuditWorkflowInput(**payload.__dict__))

    monkeypatch.setattr(main_module, 'launch_audit_workflow', _launch_inline)

    token = _login(client, seeded_ids['users']['auditor'], seeded_ids['org_id'])

    # Create two integrations used by workflow (fallback mock mode if no credentials provided).
    for provider in ['github', 'google_workspace']:
        create_integration = client.post(
            f"/projects/{seeded_ids['project_id']}/integrations",
            json={'provider': provider, 'name': provider, 'config_json': {}, 'is_enabled': True},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert create_integration.status_code == 200

    upload = client.post(
        f"/projects/{seeded_ids['project_id']}/evidence/upload",
        data={'item_type': 'manual_upload', 'metadata_json': '{"evidence_type": "policy"}'},
        files={'file': ('policy.txt', b'policy content', 'text/plain')},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert upload.status_code == 200

    run_response = client.post(
        f"/projects/{seeded_ids['project_id']}/audit-runs",
        json={'catalog_version': 'v1'},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert run_response.status_code == 200, run_response.text
    run_data = run_response.json()

    get_run = client.get(
        f"/projects/{seeded_ids['project_id']}/audit-runs/{run_data['id']}",
        headers={'Authorization': f'Bearer {token}'},
    )
    assert get_run.status_code == 200
    status = get_run.json()['status']
    assert status == 'completed'

    findings = client.get(
        f"/projects/{seeded_ids['project_id']}/audit-runs/{run_data['id']}/findings",
        headers={'Authorization': f'Bearer {token}'},
    )
    assert findings.status_code == 200

    updated_run = get_run.json()
    assert updated_run['report_evidence_id']

    report_download = client.get(
        f"/evidence/{updated_run['report_evidence_id']}/download",
        headers={'Authorization': f'Bearer {token}'},
    )
    assert report_download.status_code == 200
    assert report_download.content.startswith(b'%PDF')
