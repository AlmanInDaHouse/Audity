from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLogEntry


async def append_audit_log(
    db: AsyncSession,
    *,
    org_id: str,
    actor_user_id: str | None,
    action: str,
    entity_type: str,
    entity_id: str,
    payload: dict | None = None,
) -> AuditLogEntry:
    payload = payload or {}
    previous = await db.scalar(
        select(AuditLogEntry)
        .where(AuditLogEntry.org_id == org_id)
        .order_by(AuditLogEntry.id.desc())
        .limit(1)
    )
    prev_hash = previous.entry_hash if previous else '0' * 64

    created_at = datetime.now(UTC)
    digest_input = '|'.join(
        [
            prev_hash,
            org_id,
            actor_user_id or '',
            action,
            entity_type,
            entity_id,
            created_at.isoformat(),
            json.dumps(payload, sort_keys=True, ensure_ascii=True),
        ]
    )
    entry_hash = hashlib.sha256(digest_input.encode('utf-8')).hexdigest()

    entry = AuditLogEntry(
        org_id=org_id,
        actor_user_id=actor_user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        payload_json=payload,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        created_at=created_at,
    )
    db.add(entry)
    return entry
