import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '20s', target: 10 },
    { duration: '40s', target: 20 },
    { duration: '20s', target: 0 }
  ],
  thresholds: {
    http_req_duration: ['p(95)<1500'],
    http_req_failed: ['rate<0.05']
  }
};

const BASE = __ENV.BASE_URL || 'http://localhost:58000';
const EMAIL = __ENV.AUDIT_EMAIL || 'auditor@demo.local';
const ORG_ID = __ENV.ORG_ID || '';
const PROJECT_ID = __ENV.PROJECT_ID || '';

export default function () {
  if (!ORG_ID || !PROJECT_ID) {
    return;
  }

  const login = http.post(`${BASE}/auth/mock/login`, JSON.stringify({ email: EMAIL, org_id: ORG_ID }), {
    headers: { 'Content-Type': 'application/json' }
  });
  check(login, { 'login ok': (r) => r.status === 200 });
  if (login.status !== 200) {
    sleep(1);
    return;
  }
  const token = login.json('access_token');
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const run = http.post(`${BASE}/projects/${PROJECT_ID}/audit-runs`, JSON.stringify({ catalog_version: 'v1' }), { headers });
  check(run, { 'launch accepted': (r) => r.status === 200 || r.status === 429 });
  sleep(1);
}
