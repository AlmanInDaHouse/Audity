'use client';

import { useRouter } from 'next/navigation';
import { FormEvent, useState } from 'react';

import { apiFetch } from '@/lib/api';

const DEMO_USERS = ['admin@demo.local', 'auditor@demo.local', 'viewer@demo.local'];

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState(DEMO_USERS[1]);
  const [orgId, setOrgId] = useState('');
  const [error, setError] = useState('');

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError('');
    try {
      const res = await apiFetch('/auth/mock/login', undefined, {
        method: 'POST',
        body: JSON.stringify({ email, org_id: orgId }),
      });
      const data = await res.json();
      localStorage.setItem('audity_token', data.access_token);
      localStorage.setItem('audity_org_id', orgId);
      localStorage.setItem('audity_user_email', email);
      router.push('/projects');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    }
  }

  return (
    <main>
      <div className="card">
        <h1>Mock Login</h1>
        <p>Use seeded users and the org id printed by <code>make seed</code>.</p>
        <form onSubmit={onSubmit}>
          <div className="row">
            <div>
              <label>Email</label>
              <select value={email} onChange={(e) => setEmail(e.target.value)}>
                {DEMO_USERS.map((user) => (
                  <option key={user} value={user}>{user}</option>
                ))}
              </select>
            </div>
            <div>
              <label>Organization ID</label>
              <input value={orgId} onChange={(e) => setOrgId(e.target.value)} placeholder="UUID from seed output" required />
            </div>
          </div>
          <div style={{ marginTop: 12 }}>
            <button type="submit">Login</button>
          </div>
        </form>
        {error && <p style={{ color: '#b91c1c' }}>{error}</p>}
      </div>
    </main>
  );
}
