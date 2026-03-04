'use client';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';

export async function apiFetch(path: string, token?: string, options?: RequestInit) {
  const headers = new Headers(options?.headers || {});
  headers.set('Content-Type', 'application/json');
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `HTTP ${response.status}`);
  }
  return response;
}

export function getStoredAuth() {
  if (typeof window === 'undefined') return { token: '', orgId: '' };
  return {
    token: localStorage.getItem('audity_token') || '',
    orgId: localStorage.getItem('audity_org_id') || '',
  };
}
