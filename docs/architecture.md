# Audity MVP Architecture

## Scope
MVP funcional para auditoría normativa multi-tenant con flujo "1 click": ingesta de evidencias, evaluación, scoring de riesgo, informe HTML/PDF y remediación.

## Contexto de dominio
- Multi-tenant estricto desde el inicio: `Organization -> Project -> AuditRun`.
- Marcos soportados por catálogos versionados: ISO27001, ENS, RGPD.
- Evidencias en object store (MinIO S3-compatible) con metadata y hash SHA-256.

## Decisiones clave (why this)
- `JWT RS256 + JWKS mock OIDC`: permite integrarse como OIDC provider local sin depender de IdP externo en MVP.
- `RBAC por membership`: cada request valida token y membership activa en DB para evitar privilegios obsoletos.
- `Audit log append-only + hash chain`: dificulta manipulación y proporciona trazabilidad forense básica.
- `Temporal para orquestación`: separa API síncrona del pipeline largo de auditoría y soporta retries/visibilidad.
- `Fallback connectors`: si faltan credenciales reales en GitHub/Google, el run no se bloquea y queda trazado como mock.
- `Catálogos YAML versionados`: desacopla legal/compliance del código y habilita trazabilidad histórica por checksum.
- `Storage backend con modo memory`: facilita tests locales aislados sin MinIO, manteniendo interfaz S3 para runtime real.

## Seguridad-by-design aplicada
- Aislamiento de tenant por `org_id` en todas las consultas de negocio.
- Roles mínimos: `org_admin`, `auditor`, `client_viewer`.
- Validación de inputs con Pydantic, allowlist MIME y límites de tamaño en uploads.
- Rate limit global y sensible (`POST /projects/{id}/audit-runs` y `POST /projects/{id}/evidence/upload`).
- Secretos por variables de entorno (`.env` local, no en código).
- Headers de hardening HTTP (`X-Frame-Options`, `X-Content-Type-Options`, `CSP`, etc.).

## Componentes
- `/backend`: FastAPI + SQLAlchemy + Alembic + motor de reglas + reportes.
- `/worker`: Temporal worker Python con activities del pipeline.
- `/frontend`: Next.js mínimo para ejecutar y observar auditorías.
- `/catalogs`: catálogos y mapping multi-marco versionados.
- `/agent-rust`: scaffold para fase 2.

## Flujo "1 click"
1. `POST /projects/{id}/audit-runs` crea `AuditRun(queued)` y lanza workflow Temporal.
2. Worker ejecuta: snapshot integraciones -> recolecta evidencias -> evalúa controles -> calcula riesgo -> genera reporte -> persiste findings/tasks.
3. API expone estado y resultados por polling (`GET /projects/{id}/audit-runs/{run_id}`).
4. Reporte final PDF se guarda en MinIO y se registra en `evidence_items` tipo `report`.

## Esquema de datos
Tablas principales:
- `organizations`, `users`, `memberships`
- `projects`, `integrations`
- `control_catalogs`
- `audit_runs`, `findings`, `remediation_tasks`
- `evidence_items`
- `audit_log_entries`

## Riesgo y scoring
- Severidad: low=1, medium=3, high=5
- Resultado: pass=0, partial=0.5, fail=1
- Criticidad proyecto: low=1, medium=1.5, high=2
- Score final: normalización 0-100 y nivel low/medium/high por umbrales.

## Fase 2 prevista
- Sustituir mock OIDC por SSO real (Keycloak/Azure AD/Okta).
- Expandir conectores (AWS/Azure/GCP/MDM/EDR/SIEM).
- Agent Rust operativo para collectors distribuidos.
- Firmado de evidencias e informes con clave privada custodiada.
- Métricas/observabilidad avanzada (OTel + dashboard SLA de auditorías).

