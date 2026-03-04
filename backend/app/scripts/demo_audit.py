from __future__ import annotations

import asyncio

import httpx


async def run_demo() -> None:
    base = 'http://localhost:8000'
    print('1) Login with demo auditor and obtain token')
    print('2) Trigger POST /projects/{id}/audit-runs with that token')
    print('3) Poll GET /projects/{id}/audit-runs/{run_id}')
    print('4) Download GET /evidence/{report_id}/download')

    async with httpx.AsyncClient(timeout=30) as client:
        health = await client.get(f'{base}/health')
        print('Health:', health.text)


if __name__ == '__main__':
    asyncio.run(run_demo())
