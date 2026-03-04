from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC

import pytest
from app.db import SessionLocal, engine
from app.models import AuditLogEntry
from sqlalchemy import select, text


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
            await db.rollback()
            with pytest.raises(Exception):
                await db.execute(text('DELETE FROM audit_log_entries WHERE id=:id'), {'id': row})
                await db.commit()

    asyncio.run(_attempt_update())


def test_audit_log_hash_chain_consistency(client, seeded_ids):
    token = _login(client, seeded_ids['users']['admin'], seeded_ids['org_id'])
    for name in ['Project hash 1', 'Project hash 2']:
        response = client.post(
            f"/organizations/{seeded_ids['org_id']}/projects",
            json={'name': name, 'description': '', 'criticality': 'medium'},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert response.status_code == 200

    async def _check_chain() -> None:
        async with SessionLocal() as db:
            entries = (
                await db.execute(
                    select(AuditLogEntry)
                    .where(AuditLogEntry.org_id == seeded_ids['org_id'])
                    .order_by(AuditLogEntry.id.asc())
                )
            ).scalars().all()
            assert len(entries) >= 2

            for idx, entry in enumerate(entries):
                expected_prev = '0' * 64 if idx == 0 else entries[idx - 1].entry_hash
                assert entry.prev_hash == expected_prev

                timestamps = [entry.created_at.isoformat()]
                if entry.created_at.tzinfo is None:
                    timestamps.append(entry.created_at.replace(tzinfo=UTC).isoformat())

                hashes = []
                for created_at in timestamps:
                    digest_input = '|'.join(
                        [
                            entry.prev_hash,
                            entry.org_id,
                            entry.actor_user_id or '',
                            entry.action,
                            entry.entity_type,
                            entry.entity_id,
                            created_at,
                            json.dumps(entry.payload_json or {}, sort_keys=True, ensure_ascii=True),
                        ]
                    )
                    hashes.append(hashlib.sha256(digest_input.encode('utf-8')).hexdigest())

                assert entry.entry_hash in hashes

    asyncio.run(_check_chain())


def _login(client, email, org_id):
    res = client.post('/auth/mock/login', json={'email': email, 'org_id': org_id})
    assert res.status_code == 200
    return res.json()['access_token']
