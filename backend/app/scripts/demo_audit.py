from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
from sqlalchemy import select

from app.db import SessionLocal
from app.models import Organization, Project
from app.scripts.seed_data import seed
from app.tenancy import set_current_org


async def _find_demo_ids() -> tuple[str, str] | None:
    async with SessionLocal() as db:
        org = await db.scalar(select(Organization).where(Organization.name == 'Demo Org'))
        if org is None:
            return None
        await set_current_org(db, org.id)
        project = await db.scalar(
            select(Project).where(Project.org_id == org.id, Project.name == 'Demo Project')
        )
        if project is None:
            return None
        return org.id, project.id


async def _load_demo_ids() -> tuple[str, str]:
    demo_ids = await _find_demo_ids()
    if demo_ids is not None:
        return demo_ids

    print('Demo data missing, running seed...')
    await seed()
    demo_ids = await _find_demo_ids()
    if demo_ids is None:
        raise RuntimeError(
            'Demo Org/Project still missing after seed(). Check DATABASE_URL and migration state.'
        )
    return demo_ids


async def run_demo() -> None:
    base = 'http://localhost:8000'
    org_id, project_id = await _load_demo_ids()

    async with httpx.AsyncClient(timeout=30) as client:
        health = await client.get(f'{base}/health')
        print('Health:', health.text)

        login = await client.post(
            f'{base}/auth/mock/login',
            json={'email': 'auditor@demo.local', 'org_id': org_id},
        )
        login.raise_for_status()
        token = login.json()['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        print('Login: ok')

        run_resp = await client.post(
            f'{base}/projects/{project_id}/audit-runs',
            json={'catalog_version': 'v1'},
            headers=headers,
        )
        run_resp.raise_for_status()
        run = run_resp.json()
        run_id = run['id']
        print(f'Audit run created: {run_id}')

        final = run
        for _ in range(30):
            poll = await client.get(
                f'{base}/projects/{project_id}/audit-runs/{run_id}',
                headers=headers,
            )
            poll.raise_for_status()
            final = poll.json()
            status = final.get('status')
            print(f'Run status: {status}')
            if status in {'completed', 'failed'}:
                break
            await asyncio.sleep(2)
        else:
            raise RuntimeError('Timeout waiting for audit run completion')

        if final.get('status') != 'completed':
            raise RuntimeError(f'Audit run failed: {final}')

        report_id = final.get('report_evidence_id')
        if not report_id:
            raise RuntimeError('Audit run completed but report_evidence_id is empty')

        report_resp = await client.get(f'{base}/evidence/{report_id}/download', headers=headers)
        report_resp.raise_for_status()
        out = Path('/tmp/report_demo.pdf')
        out.write_bytes(report_resp.content)
        print(f'Report downloaded: {out} ({len(report_resp.content)} bytes)')
        print(
            f'Risk score={final.get("risk_score")} level={final.get("risk_level")} report_id={report_id}'
        )


if __name__ == '__main__':
    asyncio.run(run_demo())
