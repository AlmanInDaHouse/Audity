# Audity MVP Runbook

## Como arrancar
1. Requisitos:
   - Docker Desktop con `docker compose`.
   - (Opcional) `make`. Si no esta instalado, usar comandos `docker compose` equivalentes.
2. Levantar en limpio:
   - `docker compose down -v`
   - `docker compose up -d --build`
3. Migrar y sembrar datos:
   - `docker compose exec api uv run alembic upgrade head`
   - `docker compose exec api uv run python -m app.scripts.seed_data`
4. Comprobar salud:
   - `docker compose ps`
   - API: `http://localhost:58000/health`

## Como ejecutar demo
1. Ejecutar demo end-to-end:
   - `docker compose exec api uv run python -m app.scripts.demo_audit`
2. La demo debe mostrar:
   - Creacion de `AuditRun`.
   - Estados `queued -> running -> completed`.
   - Descarga de reporte PDF y `report_evidence_id`.
3. Verificacion opcional por API:
   - `GET /projects/{project_id}/audit-runs/{run_id}`
   - `GET /projects/{project_id}/audit-runs/{run_id}/findings`
   - `GET /projects/{project_id}/audit-runs/{run_id}/remediation-tasks`
   - `GET /evidence/{evidence_id}/download`

## Que queda para fase 2
1. SSO real (Keycloak/Azure AD/Okta) en lugar de login mock.
2. Conectores reales adicionales (AWS/Azure/GCP/MDM/EDR/SIEM).
3. Agent Rust operativo para collectors distribuidos.
4. Firma criptografica de evidencias e informes con gestion de claves.
5. Observabilidad avanzada (metricas, trazas y SLO de auditorias).
