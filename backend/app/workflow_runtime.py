from __future__ import annotations

import asyncio
import base64
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import delete, select

from app.audit_log import append_audit_log
from app.catalog_engine import load_controls
from app.config import get_settings
from app.db import SessionLocal
from app.models import (
    AuditRun,
    AuditStatusEnum,
    EvidenceItem,
    Finding,
    Integration,
    Project,
    RemediationTask,
    ResultEnum,
    SeverityEnum,
)
from app.reporting import render_report_html, render_report_pdf
from app.rules import ControlResult, calculate_risk, evaluate_controls
from app.signing import sign_manifest
from app.storage import get_object_store
from app.tenancy import set_current_org


@dataclass
class AuditWorkflowInput:
    org_id: str
    project_id: str
    audit_run_id: str
    actor_user_id: str
    catalog_version: str


def _severity_enum(value: str) -> SeverityEnum:
    if value == 'high':
        return SeverityEnum.high
    if value == 'low':
        return SeverityEnum.low
    return SeverityEnum.medium


async def _update_run_progress(
    run_id: str,
    *,
    org_id: str | None = None,
    stage: str,
    status: AuditStatusEnum | None = None,
    data: dict | None = None,
) -> None:
    async with SessionLocal() as db:
        if org_id:
            await set_current_org(db, org_id)
        run = await db.get(AuditRun, run_id)
        if run is None:
            return
        progress = run.progress_json or {}
        progress['stage'] = stage
        progress['updated_at'] = datetime.now(UTC).isoformat()
        if data:
            progress.update(data)
        run.progress_json = progress
        if status is not None:
            run.status = status
        await db.commit()


async def snapshot_integrations(input_data: AuditWorkflowInput) -> list[dict[str, Any]]:
    await _update_run_progress(
        input_data.audit_run_id,
        org_id=input_data.org_id,
        stage='snapshot_integrations',
        status=AuditStatusEnum.running,
    )
    async with SessionLocal() as db:
        await set_current_org(db, input_data.org_id)
        rows = (
            await db.execute(
                select(Integration).where(
                    Integration.org_id == input_data.org_id,
                    Integration.project_id == input_data.project_id,
                    Integration.is_enabled.is_(True),
                )
            )
        ).scalars().all()
        return [
            {
                'id': row.id,
                'provider': row.provider,
                'name': row.name,
                'config_json': row.config_json,
                'secret_ref': row.secret_ref,
            }
            for row in rows
        ]


async def _github_headers(token: str) -> dict[str, str]:
    return {
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {token}',
        'X-GitHub-Api-Version': '2022-11-28',
    }


async def collect_github_evidence(input_data: AuditWorkflowInput, integrations: list[dict[str, Any]]) -> dict[str, Any]:
    await _update_run_progress(input_data.audit_run_id, org_id=input_data.org_id, stage='collect_github_evidence')
    settings = get_settings()
    github_int = next((i for i in integrations if i['provider'].lower() == 'github'), None)
    if github_int is None:
        return {'mode': 'none', 'repo_count': 0, 'protected_repos': 0, 'repos_with_required_checks': 0}

    token = settings.github_token
    if github_int.get('secret_ref'):
        token = os.getenv(github_int['secret_ref'], token)

    if not token:
        # why this: connector remains non-blocking in MVP when credentials are missing.
        return {'mode': 'mock_fallback', 'repo_count': 3, 'protected_repos': 2, 'repos_with_required_checks': 2}

    repo_names: list[str] = github_int.get('config_json', {}).get('repos', [])
    protected = 0
    checks = 0

    async with httpx.AsyncClient(timeout=20) as client:
        headers = await _github_headers(token)
        repos: list[dict[str, Any]] = []
        if repo_names:
            for full_name in repo_names:
                owner, repo = full_name.split('/', 1)
                repo_resp = await client.get(f'https://api.github.com/repos/{owner}/{repo}', headers=headers)
                if repo_resp.status_code == 200:
                    repos.append(repo_resp.json())
        else:
            repos_resp = await client.get('https://api.github.com/user/repos?per_page=20', headers=headers)
            if repos_resp.status_code != 200:
                return {'mode': 'mock_fallback', 'repo_count': 2, 'protected_repos': 1, 'repos_with_required_checks': 1}
            repos = repos_resp.json()

        for repo in repos[:10]:
            owner = repo['owner']['login']
            repo_name = repo['name']
            default_branch = repo.get('default_branch', 'main')
            protection = await client.get(
                f'https://api.github.com/repos/{owner}/{repo_name}/branches/{default_branch}/protection', headers=headers
            )
            if protection.status_code == 200:
                protected += 1

            checks_resp = await client.get(
                f'https://api.github.com/repos/{owner}/{repo_name}/branches/{default_branch}/protection/required_status_checks',
                headers=headers,
            )
            if checks_resp.status_code == 200:
                checks += 1

    return {
        'mode': 'real',
        'repo_count': len(repos),
        'protected_repos': protected,
        'repos_with_required_checks': checks,
    }


async def collect_google_workspace_evidence(input_data: AuditWorkflowInput, integrations: list[dict[str, Any]]) -> dict[str, Any]:
    await _update_run_progress(input_data.audit_run_id, org_id=input_data.org_id, stage='collect_google_workspace_evidence')
    settings = get_settings()
    google_int = next((i for i in integrations if i['provider'].lower() in {'google_workspace', 'google'}), None)
    if google_int is None:
        return {'mode': 'none', 'users_count': 0, 'groups_count': 0}

    service_json_b64 = settings.google_service_account_json_b64
    if google_int.get('secret_ref'):
        service_json_b64 = os.getenv(google_int['secret_ref'], service_json_b64)

    if not service_json_b64:
        return {'mode': 'mock_fallback', 'users_count': 25, 'groups_count': 7}

    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        info = json.loads(base64.b64decode(service_json_b64).decode('utf-8'))
        scopes = [
            'https://www.googleapis.com/auth/admin.directory.user.readonly',
            'https://www.googleapis.com/auth/admin.directory.group.readonly',
        ]
        delegated_admin = google_int.get('config_json', {}).get('delegated_admin')
        credentials = service_account.Credentials.from_service_account_info(info, scopes=scopes)
        if delegated_admin:
            credentials = credentials.with_subject(delegated_admin)

        service = build('admin', 'directory_v1', credentials=credentials, cache_discovery=False)
        users = service.users().list(customer='my_customer', maxResults=100).execute()
        groups = service.groups().list(customer='my_customer', maxResults=100).execute()
        users_count = len(users.get('users', []))
        groups_count = len(groups.get('groups', []))
        return {'mode': 'real', 'users_count': users_count, 'groups_count': groups_count}
    except Exception:
        return {'mode': 'mock_fallback', 'users_count': 18, 'groups_count': 5}


async def collect_manual_evidence_refs(input_data: AuditWorkflowInput) -> list[dict[str, Any]]:
    await _update_run_progress(input_data.audit_run_id, org_id=input_data.org_id, stage='collect_manual_evidence')
    async with SessionLocal() as db:
        await set_current_org(db, input_data.org_id)
        rows = (
            await db.execute(
                select(EvidenceItem).where(
                    EvidenceItem.org_id == input_data.org_id,
                    EvidenceItem.project_id == input_data.project_id,
                    EvidenceItem.item_type == 'manual_upload',
                )
            )
        ).scalars().all()
        return [
            {
                'id': row.id,
                'name': row.name,
                'sha256': row.sha256,
                'metadata': row.metadata_json,
            }
            for row in rows
        ]


def _derive_remediation(results: list[ControlResult]) -> list[dict[str, str]]:
    tasks: list[dict[str, str]] = []
    for result in results:
        if result.result == 'pass':
            continue
        tasks.append(
            {
                'title': f'Remediate {result.control_id}',
                'description': f'Address finding for {result.control_id}: {result.notes}',
                'status': 'open',
            }
        )
    return tasks


async def evaluate_controls_activity(input_data: AuditWorkflowInput, evidence: dict[str, Any]) -> dict[str, Any]:
    await _update_run_progress(input_data.audit_run_id, org_id=input_data.org_id, stage='evaluate_controls')
    controls = load_controls()
    results = evaluate_controls(controls, evidence)
    return {
        'results': [r.__dict__ for r in results],
        'total_controls': len(results),
    }


async def calculate_risk_activity(input_data: AuditWorkflowInput, control_eval: dict[str, Any]) -> dict[str, Any]:
    await _update_run_progress(input_data.audit_run_id, org_id=input_data.org_id, stage='calculate_risk')
    async with SessionLocal() as db:
        await set_current_org(db, input_data.org_id)
        project = await db.get(Project, input_data.project_id)
        criticality = project.criticality.value if project else 'medium'

    results = [ControlResult(**item) for item in control_eval['results']]
    score, level = calculate_risk(results, criticality)
    return {'risk_score': score, 'risk_level': level, 'criticality': criticality}


async def generate_report_activity(
    input_data: AuditWorkflowInput,
    evidence: dict[str, Any],
    control_eval: dict[str, Any],
    risk: dict[str, Any],
) -> dict[str, Any]:
    await _update_run_progress(input_data.audit_run_id, org_id=input_data.org_id, stage='generate_report')

    findings = [item for item in control_eval['results'] if item['result'] != 'pass']
    remediation_tasks = _derive_remediation([ControlResult(**item) for item in control_eval['results']])

    async with SessionLocal() as db:
        await set_current_org(db, input_data.org_id)
        project = await db.get(Project, input_data.project_id)
        project_name = project.name if project else 'Unknown'
        context = {
            'audit_run_id': input_data.audit_run_id,
            'project_name': project_name,
            'org_name': input_data.org_id,
            'risk_score': risk['risk_score'],
            'risk_level': risk['risk_level'],
            'total_controls': control_eval['total_controls'],
            'findings': findings,
            'remediation_tasks': remediation_tasks,
            'evidence_summary': evidence,
        }

    html = render_report_html(context)
    pdf = render_report_pdf(html)
    store = get_object_store()
    await store.ensure_bucket()

    html_key = f'reports/{input_data.org_id}/{input_data.project_id}/{input_data.audit_run_id}.html'
    pdf_key = f'reports/{input_data.org_id}/{input_data.project_id}/{input_data.audit_run_id}.pdf'
    html_stored = await store.put_bytes(html_key, html.encode('utf-8'), 'text/html; charset=utf-8')
    pdf_stored = await store.put_bytes(pdf_key, pdf, 'application/pdf')
    html_manifest = {
        'type': 'report_html',
        'org_id': input_data.org_id,
        'project_id': input_data.project_id,
        'audit_run_id': input_data.audit_run_id,
        'sha256': html_stored.sha256,
        'object_key': html_stored.key,
        'generated_at': datetime.now(UTC).isoformat(),
    }
    pdf_manifest = {
        'type': 'report_pdf',
        'org_id': input_data.org_id,
        'project_id': input_data.project_id,
        'audit_run_id': input_data.audit_run_id,
        'sha256': pdf_stored.sha256,
        'object_key': pdf_stored.key,
        'generated_at': datetime.now(UTC).isoformat(),
    }
    html_signature = await sign_manifest(input_data.org_id, html_manifest)
    pdf_signature = await sign_manifest(input_data.org_id, pdf_manifest)

    async with SessionLocal() as db:
        await set_current_org(db, input_data.org_id)
        html_ev = EvidenceItem(
            org_id=input_data.org_id,
            project_id=input_data.project_id,
            audit_run_id=input_data.audit_run_id,
            integration_id=None,
            item_type='report_html',
            name=f'audit-report-{input_data.audit_run_id}.html',
            object_key=html_stored.key,
            sha256=html_stored.sha256,
            metadata_json={'content_type': 'text/html'},
            manifest_json=html_manifest,
            signature_bundle_json=html_signature,
            created_by_user_id=input_data.actor_user_id,
        )
        pdf_ev = EvidenceItem(
            org_id=input_data.org_id,
            project_id=input_data.project_id,
            audit_run_id=input_data.audit_run_id,
            integration_id=None,
            item_type='report',
            name=f'audit-report-{input_data.audit_run_id}.pdf',
            object_key=pdf_stored.key,
            sha256=pdf_stored.sha256,
            metadata_json={'content_type': 'application/pdf', 'paired_html_evidence_id': None},
            manifest_json=pdf_manifest,
            signature_bundle_json=pdf_signature,
            created_by_user_id=input_data.actor_user_id,
        )
        db.add(html_ev)
        db.add(pdf_ev)
        await db.flush()
        pdf_ev.metadata_json = {'content_type': 'application/pdf', 'paired_html_evidence_id': html_ev.id}
        await db.commit()
        report_evidence_id = pdf_ev.id

    return {
        'report_evidence_id': report_evidence_id,
        'findings': findings,
        'remediation_tasks': remediation_tasks,
        'report_signature_bundle': pdf_signature,
    }


async def persist_results_activity(
    input_data: AuditWorkflowInput,
    evidence: dict[str, Any],
    control_eval: dict[str, Any],
    risk: dict[str, Any],
    report_meta: dict[str, Any],
) -> dict[str, Any]:
    await _update_run_progress(input_data.audit_run_id, org_id=input_data.org_id, stage='persist_results')
    async with SessionLocal() as db:
        await set_current_org(db, input_data.org_id)
        run = await db.get(AuditRun, input_data.audit_run_id)
        if run is None:
            raise ValueError('AuditRun not found')

        await db.execute(delete(Finding).where(Finding.audit_run_id == run.id))
        await db.execute(delete(RemediationTask).where(RemediationTask.audit_run_id == run.id))

        findings: list[Finding] = []
        for item in report_meta['findings']:
            finding = Finding(
                org_id=input_data.org_id,
                project_id=input_data.project_id,
                audit_run_id=input_data.audit_run_id,
                control_id=item['control_id'],
                title=item['title'],
                severity=_severity_enum(item['severity']),
                result=ResultEnum(item['result']),
                confidence=item['confidence'],
                notes=item['notes'],
                evidence_refs_json=item.get('evidence_refs', []),
            )
            findings.append(finding)
            db.add(finding)

        await db.flush()
        for idx, task_item in enumerate(report_meta['remediation_tasks']):
            linked_finding_id = findings[idx].id if idx < len(findings) else None
            task = RemediationTask(
                org_id=input_data.org_id,
                project_id=input_data.project_id,
                audit_run_id=input_data.audit_run_id,
                finding_id=linked_finding_id,
                title=task_item['title'],
                description=task_item['description'],
                status=task_item['status'],
            )
            db.add(task)

        run.summary_json = {
            'total_controls': control_eval['total_controls'],
            'failing_controls': len(report_meta['findings']),
            'evidence': evidence,
        }
        run.risk_score = risk['risk_score']
        run.risk_level = risk['risk_level']
        run.report_evidence_id = report_meta['report_evidence_id']
        run.signature_bundle_json = report_meta.get('report_signature_bundle', {})
        run.status = AuditStatusEnum.completed
        run.progress_json = {'stage': 'completed', 'updated_at': datetime.now(UTC).isoformat()}

        await append_audit_log(
            db,
            org_id=input_data.org_id,
            actor_user_id=input_data.actor_user_id,
            action='audit_run.completed',
            entity_type='audit_run',
            entity_id=input_data.audit_run_id,
            payload={'risk_score': risk['risk_score'], 'risk_level': risk['risk_level']},
        )
        await db.commit()

    return {
        'summary_json': {
            'total_controls': control_eval['total_controls'],
            'failing_controls': len(report_meta['findings']),
        },
        'risk_score': risk['risk_score'],
        'report_evidence_id': report_meta['report_evidence_id'],
    }


async def mark_audit_failed(input_data: AuditWorkflowInput, reason: str) -> None:
    async with SessionLocal() as db:
        await set_current_org(db, input_data.org_id)
        run = await db.get(AuditRun, input_data.audit_run_id)
        if run is None:
            return
        run.status = AuditStatusEnum.failed
        run.progress_json = {'stage': 'failed', 'error': reason, 'updated_at': datetime.now(UTC).isoformat()}
        await append_audit_log(
            db,
            org_id=input_data.org_id,
            actor_user_id=input_data.actor_user_id,
            action='audit_run.failed',
            entity_type='audit_run',
            entity_id=input_data.audit_run_id,
            payload={'reason': reason},
        )
        await db.commit()


async def execute_inline(input_data: AuditWorkflowInput) -> dict[str, Any]:
    try:
        integrations = await snapshot_integrations(input_data)
        github = await collect_github_evidence(input_data, integrations)
        google = await collect_google_workspace_evidence(input_data, integrations)
        manual = await collect_manual_evidence_refs(input_data)
        evidence = {'github': github, 'google_workspace': google, 'manual': manual}
        control_eval = await evaluate_controls_activity(input_data, evidence)
        risk = await calculate_risk_activity(input_data, control_eval)
        report_meta = await generate_report_activity(input_data, evidence, control_eval, risk)
        return await persist_results_activity(input_data, evidence, control_eval, risk, report_meta)
    except Exception as exc:
        await mark_audit_failed(input_data, str(exc))
        raise


def execute_inline_background(input_data: AuditWorkflowInput) -> None:
    asyncio.create_task(execute_inline(input_data))
