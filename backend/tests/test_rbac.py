from __future__ import annotations


def test_rbac_blocks_viewer_project_create(client, seeded_ids):
    token = login(client, seeded_ids['users']['viewer'], seeded_ids['org_id'])
    response = client.post(
        f"/organizations/{seeded_ids['org_id']}/projects",
        json={'name': 'Blocked', 'description': 'nope', 'criticality': 'medium'},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert response.status_code == 403


def test_rbac_allows_auditor_project_create(client, seeded_ids):
    token = login(client, seeded_ids['users']['auditor'], seeded_ids['org_id'])
    response = client.post(
        f"/organizations/{seeded_ids['org_id']}/projects",
        json={'name': 'Allowed', 'description': 'ok', 'criticality': 'low'},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert response.status_code == 200
    data = response.json()
    assert data['name'] == 'Allowed'


def login(client, email, org_id):
    res = client.post('/auth/mock/login', json={'email': email, 'org_id': org_id})
    assert res.status_code == 200
    return res.json()['access_token']
