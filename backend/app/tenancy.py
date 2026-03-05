from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def set_current_org(db: AsyncSession, org_id: str) -> None:
    if not org_id:
        return
    # why this: Postgres RLS policies key off app.current_org_id.
    # We set it at session level to survive commit/refresh within one request lifecycle.
    try:
        await db.execute(text("SELECT set_config('app.current_org_id', :org_id, false)"), {'org_id': org_id})
    except Exception:
        # SQLite tests and non-Postgres backends do not support set_config.
        return
