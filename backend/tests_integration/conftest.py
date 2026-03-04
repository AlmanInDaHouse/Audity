from __future__ import annotations

import os
import uuid
from typing import Any

import asyncpg
import pytest
import pytest_asyncio


def _pg_dsn() -> str:
    raw = os.getenv('DATABASE_URL', 'postgresql+asyncpg://audity:audity@postgres:5432/audity')
    return raw.replace('postgresql+asyncpg://', 'postgresql://', 1)


@pytest.fixture(scope='session')
def api_base_url() -> str:
    return os.getenv('INTEGRATION_BASE_URL', 'http://127.0.0.1:8000').rstrip('/')


@pytest_asyncio.fixture
async def org_context() -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:8]
    org_a_id = str(uuid.uuid4())
    org_b_id = str(uuid.uuid4())
    admin_a_id = str(uuid.uuid4())
    auditor_a_id = str(uuid.uuid4())
    viewer_a_id = str(uuid.uuid4())
    admin_b_id = str(uuid.uuid4())
    project_a_id = str(uuid.uuid4())
    project_b_id = str(uuid.uuid4())
    run_b_id = str(uuid.uuid4())
    evidence_b_id = str(uuid.uuid4())

    admin_a_email = f'it.admina.{suffix}@test.local'
    auditor_a_email = f'it.auditor.{suffix}@test.local'
    viewer_a_email = f'it.viewer.{suffix}@test.local'
    admin_b_email = f'it.adminb.{suffix}@test.local'

    conn = await asyncpg.connect(_pg_dsn())
    try:
        await conn.execute('INSERT INTO organizations (id, name, created_at) VALUES ($1, $2, now())', org_a_id, f'IT Org A {suffix}')
        await conn.execute('INSERT INTO organizations (id, name, created_at) VALUES ($1, $2, now())', org_b_id, f'IT Org B {suffix}')

        await conn.execute(
            'INSERT INTO users (id, email, display_name, created_at) VALUES ($1, $2, $3, now())',
            admin_a_id,
            admin_a_email,
            'IT Admin A',
        )
        await conn.execute(
            'INSERT INTO users (id, email, display_name, created_at) VALUES ($1, $2, $3, now())',
            auditor_a_id,
            auditor_a_email,
            'IT Auditor A',
        )
        await conn.execute(
            'INSERT INTO users (id, email, display_name, created_at) VALUES ($1, $2, $3, now())',
            viewer_a_id,
            viewer_a_email,
            'IT Viewer A',
        )
        await conn.execute(
            'INSERT INTO users (id, email, display_name, created_at) VALUES ($1, $2, $3, now())',
            admin_b_id,
            admin_b_email,
            'IT Admin B',
        )

        await conn.execute(
            "INSERT INTO memberships (id, org_id, user_id, role, created_at) VALUES ($1, $2, $3, 'org_admin'::roleenum, now())",
            str(uuid.uuid4()),
            org_a_id,
            admin_a_id,
        )
        await conn.execute(
            "INSERT INTO memberships (id, org_id, user_id, role, created_at) VALUES ($1, $2, $3, 'auditor'::roleenum, now())",
            str(uuid.uuid4()),
            org_a_id,
            auditor_a_id,
        )
        await conn.execute(
            "INSERT INTO memberships (id, org_id, user_id, role, created_at) VALUES ($1, $2, $3, 'client_viewer'::roleenum, now())",
            str(uuid.uuid4()),
            org_a_id,
            viewer_a_id,
        )
        await conn.execute(
            "INSERT INTO memberships (id, org_id, user_id, role, created_at) VALUES ($1, $2, $3, 'org_admin'::roleenum, now())",
            str(uuid.uuid4()),
            org_b_id,
            admin_b_id,
        )

        await conn.execute(
            "INSERT INTO projects (id, org_id, name, description, criticality, created_at) VALUES ($1, $2, $3, $4, 'medium'::criticalityenum, now())",
            project_a_id,
            org_a_id,
            f'IT Project A {suffix}',
            'integration test project',
        )
        await conn.execute(
            "INSERT INTO projects (id, org_id, name, description, criticality, created_at) VALUES ($1, $2, $3, $4, 'high'::criticalityenum, now())",
            project_b_id,
            org_b_id,
            f'IT Project B {suffix}',
            'integration test project',
        )

        await conn.execute(
            """
            INSERT INTO audit_runs
            (id, org_id, project_id, triggered_by_user_id, status, catalog_version, progress_json, summary_json, risk_score, risk_level, report_evidence_id, created_at, updated_at)
            VALUES
            ($1, $2, $3, $4, 'completed'::auditstatusenum, 'v1', '{"stage":"completed"}'::json, '{}'::json, NULL, NULL, NULL, now(), now())
            """,
            run_b_id,
            org_b_id,
            project_b_id,
            admin_b_id,
        )

        await conn.execute(
            """
            INSERT INTO evidence_items
            (id, org_id, project_id, audit_run_id, integration_id, item_type, name, object_key, sha256, metadata_json, created_by_user_id, created_at)
            VALUES
            ($1, $2, $3, $4, NULL, 'report', $5, $6, $7, '{"content_type":"application/pdf"}'::json, $8, now())
            """,
            evidence_b_id,
            org_b_id,
            project_b_id,
            run_b_id,
            'tenant-b-report.pdf',
            f'reports/integration/{suffix}.pdf',
            '0' * 64,
            admin_b_id,
        )
    finally:
        await conn.close()

    return {
        'org_a_id': org_a_id,
        'org_b_id': org_b_id,
        'project_a_id': project_a_id,
        'project_b_id': project_b_id,
        'run_b_id': run_b_id,
        'evidence_b_id': evidence_b_id,
        'users': {
            'admin_a': admin_a_email,
            'auditor_a': auditor_a_email,
            'viewer_a': viewer_a_email,
            'admin_b': admin_b_email,
        },
    }
