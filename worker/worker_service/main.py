from __future__ import annotations

import asyncio

from temporalio.client import Client
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from app.config import get_settings
from app.temporal_workflow import ACTIVITIES, AuditRunWorkflow


async def run_worker() -> None:
    settings = get_settings()
    client = await Client.connect(settings.temporal_server, namespace=settings.temporal_namespace)
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[AuditRunWorkflow],
        activities=ACTIVITIES,
        workflow_runner=UnsandboxedWorkflowRunner(),
        max_concurrent_activities=settings.temporal_max_concurrent_activities,
        max_concurrent_workflow_tasks=settings.temporal_max_concurrent_workflow_tasks,
    )
    await worker.run()


if __name__ == '__main__':
    asyncio.run(run_worker())
