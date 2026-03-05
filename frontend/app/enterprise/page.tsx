'use client';

import { FormEvent, useEffect, useState } from 'react';

import { apiFetch, getStoredAuth } from '@/lib/api';

export default function EnterprisePage() {
  const [orgId, setOrgId] = useState('');
  const [features, setFeatures] = useState<Record<string, unknown>>({});
  const [planCode, setPlanCode] = useState('enterprise');
  const [maxAssets, setMaxAssets] = useState(500);
  const [maxUploadMb, setMaxUploadMb] = useState(100);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    const auth = getStoredAuth();
    setOrgId(auth.orgId);
    apiFetch('/enterprise/features', auth.token)
      .then((res) => res.json())
      .then((data) => setFeatures(data))
      .catch((err) => setError(err instanceof Error ? err.message : 'Could not load enterprise features'));
  }, []);

  async function savePlan(event: FormEvent) {
    event.preventDefault();
    const { token } = getStoredAuth();
    setError('');
    setMessage('');
    try {
      const res = await apiFetch(`/organizations/${orgId}/pricing-plan`, token, {
        method: 'PUT',
        body: JSON.stringify({
          plan_code: planCode,
          max_assets: maxAssets,
          max_upload_bytes: maxUploadMb * 1024 * 1024,
          modules_json: {
            approvals: true,
            reporting_package: true,
            scim: true
          }
        })
      });
      const data = await res.json();
      setMessage(`Plan updated: ${data.plan_code}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save plan');
    }
  }

  return (
    <main>
      <div className="card">
        <h1>Enterprise Controls</h1>
        <p>Manage pricing gates and check feature flags.</p>
        {error && <p style={{ color: '#b91c1c' }}>{error}</p>}
        {message && <p style={{ color: '#166534' }}>{message}</p>}
      </div>
      <div className="card">
        <h2>Feature Flags</h2>
        <pre>{JSON.stringify(features, null, 2)}</pre>
      </div>
      <div className="card">
        <h2>Pricing Plan</h2>
        <form onSubmit={savePlan}>
          <label>Plan code</label>
          <input value={planCode} onChange={(e) => setPlanCode(e.target.value)} />
          <label>Max assets</label>
          <input type="number" value={maxAssets} onChange={(e) => setMaxAssets(Number(e.target.value || 0))} />
          <label>Max upload (MB)</label>
          <input type="number" value={maxUploadMb} onChange={(e) => setMaxUploadMb(Number(e.target.value || 0))} />
          <div style={{ marginTop: 12 }}>
            <button type="submit">Save plan</button>
          </div>
        </form>
      </div>
    </main>
  );
}
