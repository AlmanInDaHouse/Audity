'use client';

import { useParams } from 'next/navigation';
import { useEffect, useState } from 'react';

import { apiFetch, getStoredAuth } from '@/lib/api';

type AuditRun = {
  id: string;
  status: string;
  risk_score?: number;
  risk_level?: string;
  progress_json: Record<string, unknown>;
  report_evidence_id?: string;
};

type Finding = {
  id: string;
  control_id: string;
  severity: string;
  result: string;
  notes: string;
};

export default function ProjectDetailPage() {
  const params = useParams<{ id: string }>();
  const projectId = params.id;
  const [run, setRun] = useState<AuditRun | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function startRun() {
    const { token } = getStoredAuth();
    setBusy(true);
    setError('');
    try {
      const res = await apiFetch(`/projects/${projectId}/audit-runs`, token, {
        method: 'POST',
        body: JSON.stringify({ catalog_version: 'v1' }),
      });
      const data = await res.json();
      setRun(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start run');
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!run) return;
    const { token } = getStoredAuth();
    const timer = setInterval(async () => {
      try {
        const res = await apiFetch(`/projects/${projectId}/audit-runs/${run.id}`, token);
        const data = await res.json();
        setRun(data);

        if (data.status === 'completed' || data.status === 'failed') {
          clearInterval(timer);
        }

        if (data.status === 'completed') {
          const findingsRes = await apiFetch(`/projects/${projectId}/audit-runs/${run.id}/findings`, token);
          setFindings(await findingsRes.json());
        }
      } catch {
        clearInterval(timer);
      }
    }, 2500);
    return () => clearInterval(timer);
  }, [run?.id, projectId]);

  async function downloadReport() {
    if (!run?.report_evidence_id) return;
    const { token } = getStoredAuth();
    const base = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';
    const response = await fetch(`${base}/evidence/${run.report_evidence_id}/download`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
      setError('Could not download report');
      return;
    }
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `audit-report-${run.id}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  }

  return (
    <main>
      <div className="card">
        <h1>Project {projectId}</h1>
        <button onClick={startRun} disabled={busy}>{busy ? 'Starting...' : 'Run audit'}</button>
        {error && <p style={{ color: '#b91c1c' }}>{error}</p>}
      </div>

      {run && (
        <div className="card">
          <h2>Run status</h2>
          <p>ID: {run.id}</p>
          <p>Status: <strong>{run.status}</strong></p>
          <p>Stage: {String(run.progress_json?.stage || 'n/a')}</p>
          <p>Risk: {run.risk_score ?? '-'} ({run.risk_level ?? '-'})</p>
          {run.report_evidence_id && <button className="secondary" onClick={downloadReport}>Download PDF report</button>}
        </div>
      )}

      {findings.length > 0 && (
        <div className="card">
          <h2>Findings</h2>
          {findings.map((finding) => (
            <div key={finding.id} className="card">
              <strong>{finding.control_id}</strong> - {finding.result} ({finding.severity})
              <p>{finding.notes}</p>
            </div>
          ))}
        </div>
      )}
    </main>
  );
}
