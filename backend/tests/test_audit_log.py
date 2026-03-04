from __future__ import annotations

import asyncio

import pytest
from app.db import SessionLocal, engine
from sqlalchemy import text


def test_audit_log_is_append_only_in_postgres(client, seeded_ids):
    if engine.dialect.name != 'postgresql':
        pytest.skip('append-only trigger is postgres-specific')

    token = _login(client, seeded_ids['users']['admin'], seeded_ids['org_id'])
    response = client.post(
        f"/organizations/{seeded_ids['org_id']}/projects",
        json={'name': 'Project for audit log', 'description': '', 'criticality': 'medium'},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert response.status_code == 200

    async def _attempt_update() -> None:
        async with SessionLocal() as db:
            row = await db.scalar(text('SELECT id FROM audit_log_entries ORDER BY id DESC LIMIT 1'))
            assert row is not None
            with pytest.raises(Exception):
                await db.execute(text("UPDATE audit_log_entries SET action='tamper' WHERE id=:id"), {'id': row})
                await db.commit()

    asyncio.run(_attempt_update())


def _login(client, email, org_id):
    res = client.post('/auth/mock/login', json={'email': email, 'org_id': org_id})
    assert res.status_code == 200
    return res.json()['access_token']
