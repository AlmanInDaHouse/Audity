from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Any

from temporalio import activity, workflow
from temporalio.common import RetryPolicy

from app.av_scanner import scan_upload_activity
from app.workflow_runtime import (
    AuditWorkflowInput,
    calculate_risk_activity,
    collect_github_evidence,
    collect_google_workspace_evidence,
    collect_manual_evidence_refs,
    evaluate_controls_activity,
    generate_report_activity,
    mark_audit_failed,
    persist_results_activity,
    snapshot_integrations,
)


@dataclass
class AuditRunWorkflowInput:
    org_id: str
    project_id: str
    audit_run_id: str
    actor_user_id: str
    catalog_version: str


@activity.defn
async def snapshot_integrations_activity(input_data: dict[str, Any]) -> list[dict[str, Any]]:
    return await snapshot_integrations(AuditWorkflowInput(**input_data))


@activity.defn
async def collect_github_evidence_activity(input_data: dict[str, Any], integrations: list[dict[str, Any]]) -> dict[str, Any]:
    return await collect_github_evidence(AuditWorkflowInput(**input_data), integrations)


@activity.defn
async def collect_google_workspace_evidence_activity(input_data: dict[str, Any], integrations: list[dict[str, Any]]) -> dict[str, Any]:
    return await collect_google_workspace_evidence(AuditWorkflowInput(**input_data), integrations)


@activity.defn
async def collect_manual_evidence_refs_activity(input_data: dict[str, Any]) -> list[dict[str, Any]]:
    return await collect_manual_evidence_refs(AuditWorkflowInput(**input_data))


@activity.defn
async def evaluate_controls_activity_wrapper(input_data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    return await evaluate_controls_activity(AuditWorkflowInput(**input_data), evidence)


@activity.defn
async def calculate_risk_activity_wrapper(input_data: dict[str, Any], control_eval: dict[str, Any]) -> dict[str, Any]:
    return await calculate_risk_activity(AuditWorkflowInput(**input_data), control_eval)


@activity.defn
async def generate_report_activity_wrapper(
    input_data: dict[str, Any],
    evidence: dict[str, Any],
    control_eval: dict[str, Any],
    risk: dict[str, Any],
) -> dict[str, Any]:
    return await generate_report_activity(AuditWorkflowInput(**input_data), evidence, control_eval, risk)


@activity.defn
async def persist_results_activity_wrapper(
    input_data: dict[str, Any],
    evidence: dict[str, Any],
    control_eval: dict[str, Any],
    risk: dict[str, Any],
    report_meta: dict[str, Any],
) -> dict[str, Any]:
    return await persist_results_activity(AuditWorkflowInput(**input_data), evidence, control_eval, risk, report_meta)


@activity.defn
async def mark_audit_failed_activity(input_data: dict[str, Any], reason: str) -> None:
    await mark_audit_failed(AuditWorkflowInput(**input_data), reason)


@activity.defn
async def scan_upload_activity_wrapper(content: bytes) -> str:
    return await scan_upload_activity(content)


@workflow.defn
class AuditRunWorkflow:
    @workflow.run
    async def run(self, input_payload: AuditRunWorkflowInput) -> dict[str, Any]:
        payload = asdict(input_payload)

        timeout = timedelta(minutes=5)
        retry = RetryPolicy(
            initial_interval=timedelta(seconds=2),
            backoff_coefficient=2.0,
            maximum_interval=timedelta(seconds=30),
            maximum_attempts=3,
        )

        try:
            integrations = await workflow.execute_activity(
                snapshot_integrations_activity,
                payload,
                schedule_to_close_timeout=timeout,
                retry_policy=retry,
            )
            github = await workflow.execute_activity(
                collect_github_evidence_activity,
                args=[payload, integrations],
                schedule_to_close_timeout=timeout,
                retry_policy=retry,
            )
            google = await workflow.execute_activity(
                collect_google_workspace_evidence_activity,
                args=[payload, integrations],
                schedule_to_close_timeout=timeout,
                retry_policy=retry,
            )
            manual = await workflow.execute_activity(
                collect_manual_evidence_refs_activity,
                payload,
                schedule_to_close_timeout=timeout,
                retry_policy=retry,
            )
            evidence = {'github': github, 'google_workspace': google, 'manual': manual}
            control_eval = await workflow.execute_activity(
                evaluate_controls_activity_wrapper,
                args=[payload, evidence],
                schedule_to_close_timeout=timeout,
                retry_policy=retry,
            )
            risk = await workflow.execute_activity(
                calculate_risk_activity_wrapper,
                args=[payload, control_eval],
                schedule_to_close_timeout=timeout,
                retry_policy=retry,
            )
            report_meta = await workflow.execute_activity(
                generate_report_activity_wrapper,
                args=[payload, evidence, control_eval, risk],
                schedule_to_close_timeout=timeout,
                retry_policy=retry,
            )
            return await workflow.execute_activity(
                persist_results_activity_wrapper,
                args=[payload, evidence, control_eval, risk, report_meta],
                schedule_to_close_timeout=timeout,
                retry_policy=retry,
            )
        except Exception as exc:
            await workflow.execute_activity(
                mark_audit_failed_activity,
                args=[payload, str(exc)],
                schedule_to_close_timeout=timeout,
            )
            raise


ACTIVITIES = [
    snapshot_integrations_activity,
    collect_github_evidence_activity,
    collect_google_workspace_evidence_activity,
    collect_manual_evidence_refs_activity,
    evaluate_controls_activity_wrapper,
    calculate_risk_activity_wrapper,
    generate_report_activity_wrapper,
    persist_results_activity_wrapper,
    mark_audit_failed_activity,
    scan_upload_activity_wrapper,
]
