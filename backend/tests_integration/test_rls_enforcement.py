from __future__ import annotations

import asyncpg
import pytest

from tests_integration.conftest import _pg_dsn


@pytest.mark.asyncio
async def test_postgres_rls_blocks_cross_tenant_even_without_app_filter(org_context):
    conn = await asyncpg.connect(_pg_dsn())
    try:
        await conn.execute("SELECT set_config('app.current_org_id', $1, false)", org_context['org_a_id'])

        own_project = await conn.fetchval(
            'SELECT id FROM projects WHERE id = $1',
            org_context['project_a_id'],
        )
        foreign_project = await conn.fetchval(
            'SELECT id FROM projects WHERE id = $1',
            org_context['project_b_id'],
        )
        assert own_project == org_context['project_a_id']
        assert foreign_project is None

        updated = await conn.execute(
            "UPDATE projects SET description='forbidden-update' WHERE id=$1",
            org_context['project_b_id'],
        )
        assert updated.endswith('0')
    finally:
        await conn.close()
