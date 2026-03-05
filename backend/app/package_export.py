from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime

from app.models import AuditRun, EvidenceItem, Finding, Project, RemediationTask
from app.storage import get_object_store


async def build_auditor_package(
    *,
    org_id: str,
    project: Project,
    run: AuditRun,
    findings: list[Finding],
    tasks: list[RemediationTask],
    evidence_items: list[EvidenceItem],
) -> bytes:
    store = get_object_store()
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
        manifest = {
            'generated_at': datetime.now(UTC).isoformat(),
            'org_id': org_id,
            'project_id': project.id,
            'project_name': project.name,
            'audit_run_id': run.id,
            'risk_score': run.risk_score,
            'risk_level': run.risk_level,
            'evidence_count': len(evidence_items),
        }
        archive.writestr('manifest.json', json.dumps(manifest, indent=2))
        archive.writestr(
            'findings.json',
            json.dumps(
                [
                    {
                        'id': f.id,
                        'control_id': f.control_id,
                        'result': f.result.value,
                        'severity': f.severity.value,
                        'notes': f.notes,
                        'signature_bundle': f'{f.id}.json',
                    }
                    for f in findings
                ],
                indent=2,
            ),
        )
        archive.writestr(
            'remediation_tasks.json',
            json.dumps(
                [
                    {
                        'id': t.id,
                        'finding_id': t.finding_id,
                        'title': t.title,
                        'description': t.description,
                        'status': t.status,
                        'due_date': t.due_date.isoformat() if t.due_date else None,
                    }
                    for t in tasks
                ],
                indent=2,
            ),
        )
        for evidence in evidence_items:
            archive.writestr(
                f'signatures/{evidence.id}.json',
                json.dumps(evidence.signature_bundle_json or {}, indent=2),
            )
            archive.writestr(
                f'evidence-metadata/{evidence.id}.json',
                json.dumps(
                    {
                        'id': evidence.id,
                        'name': evidence.name,
                        'sha256': evidence.sha256,
                        'metadata': evidence.metadata_json,
                        'scan_status': evidence.scan_status,
                    },
                    indent=2,
                ),
            )
            try:
                content = await store.get_bytes(evidence.object_key)
                archive.writestr(f'evidence/{evidence.name}', content)
            except Exception:
                archive.writestr(f'evidence/{evidence.name}.missing.txt', 'Object unavailable in store')
    return output.getvalue()
