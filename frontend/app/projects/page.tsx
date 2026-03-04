'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';

import { apiFetch, getStoredAuth } from '@/lib/api';

type Project = {
  id: string;
  name: string;
  description: string;
  criticality: string;
};

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const { token, orgId } = getStoredAuth();
    if (!token || !orgId) {
      setError('Missing session. Login again.');
      return;
    }

    apiFetch(`/organizations/${orgId}/projects`, token)
      .then((res) => res.json())
      .then((data) => setProjects(data))
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load projects'));
  }, []);

  return (
    <main>
      <div className="card">
        <h1>Projects</h1>
        <p>Run and monitor compliance audits.</p>
        {error && <p style={{ color: '#b91c1c' }}>{error}</p>}
        {projects.length === 0 && <p>No projects found.</p>}
        {projects.map((project) => (
          <div className="card" key={project.id}>
            <h3>{project.name}</h3>
            <p>{project.description}</p>
            <p>Criticality: <strong>{project.criticality}</strong></p>
            <Link href={`/projects/${project.id}`}>Open project</Link>
          </div>
        ))}
      </div>
    </main>
  );
}
