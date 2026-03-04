from __future__ import annotations

from app import main as main_module
from app.rate_limit import rate_limiter


def _login(client, email: str, org_id: str) -> str:
    res = client.post('/auth/mock/login', json={'email': email, 'org_id': org_id})
    assert res.status_code == 200, res.text
    return res.json()['access_token']


def _reset_rate_limit_state() -> None:
    rate_limiter._memory.clear()
    rate_limiter._memory_expiry.clear()


def test_upload_rejects_disallowed_mime(client, seeded_ids):
    token = _login(client, seeded_ids['users']['auditor'], seeded_ids['org_id'])
    response = client.post(
        f"/projects/{seeded_ids['project_id']}/evidence/upload",
        data={'item_type': 'manual_upload', 'metadata_json': '{}'},
        files={'file': ('bad.exe', b'MZ-binary', 'application/x-msdownload')},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert response.status_code == 415


def test_upload_rejects_file_too_large(client, seeded_ids):
    token = _login(client, seeded_ids['users']['auditor'], seeded_ids['org_id'])
    too_large = b'a' * (20 * 1024 * 1024 + 1)
    response = client.post(
        f"/projects/{seeded_ids['project_id']}/evidence/upload",
        data={'item_type': 'manual_upload', 'metadata_json': '{}'},
        files={'file': ('large.txt', too_large, 'text/plain')},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert response.status_code == 413


def test_sensitive_rate_limit_applies_to_audit_runs(client, seeded_ids, monkeypatch):
    async def _noop_launch(_payload) -> None:
        return None

    monkeypatch.setattr(main_module, 'launch_audit_workflow', _noop_launch)
    token = _login(client, seeded_ids['users']['auditor'], seeded_ids['org_id'])
    headers = {'Authorization': f'Bearer {token}'}

    previous_limit = rate_limiter.settings.sensitive_rate_limit_per_minute
    rate_limiter.settings.sensitive_rate_limit_per_minute = 1
    _reset_rate_limit_state()
    try:
        first = client.post(
            f"/projects/{seeded_ids['project_id']}/audit-runs",
            json={'catalog_version': 'v1'},
            headers=headers,
        )
        second = client.post(
            f"/projects/{seeded_ids['project_id']}/audit-runs",
            json={'catalog_version': 'v1'},
            headers=headers,
        )
    finally:
        rate_limiter.settings.sensitive_rate_limit_per_minute = previous_limit
        _reset_rate_limit_state()

    assert first.status_code == 200
    assert second.status_code == 429


def test_sensitive_rate_limit_applies_to_evidence_upload(client, seeded_ids):
    token = _login(client, seeded_ids['users']['auditor'], seeded_ids['org_id'])
    headers = {'Authorization': f'Bearer {token}'}

    previous_limit = rate_limiter.settings.sensitive_rate_limit_per_minute
    rate_limiter.settings.sensitive_rate_limit_per_minute = 1
    _reset_rate_limit_state()
    try:
        first = client.post(
            f"/projects/{seeded_ids['project_id']}/evidence/upload",
            data={'item_type': 'manual_upload', 'metadata_json': '{}'},
            files={'file': ('ok.txt', b'first', 'text/plain')},
            headers=headers,
        )
        second = client.post(
            f"/projects/{seeded_ids['project_id']}/evidence/upload",
            data={'item_type': 'manual_upload', 'metadata_json': '{}'},
            files={'file': ('ok2.txt', b'second', 'text/plain')},
            headers=headers,
        )
    finally:
        rate_limiter.settings.sensitive_rate_limit_per_minute = previous_limit
        _reset_rate_limit_state()

    assert first.status_code == 200
    assert second.status_code == 429
