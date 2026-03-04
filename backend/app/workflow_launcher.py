from __future__ import annotations

from temporalio.client import Client

from app.config import get_settings
from app.temporal_workflow import AuditRunWorkflow, AuditRunWorkflowInput
from app.workflow_runtime import AuditWorkflowInput, execute_inline_background


async def launch_audit_workflow(payload: AuditRunWorkflowInput) -> None:
    settings = get_settings()
    if settings.workflow_mode == 'inline':
        execute_inline_background(AuditWorkflowInput(**payload.__dict__))
        return

    client = await Client.connect(settings.temporal_server, namespace=settings.temporal_namespace)
    await client.start_workflow(
        AuditRunWorkflow.run,
        payload,
        id=f'audit-run-{payload.audit_run_id}',
        task_queue=settings.temporal_task_queue,
    )
