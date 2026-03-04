# Acceptance Report - MVP "Auditoria en 1 click"

Fecha de ejecucion: 2026-03-04  
Repositorio: `C:\Users\manue\Desktop\Audity`

## 1) Checklist A->G

### A) Repo e infra
- [x] A1 Monorepo validado: `backend/`, `worker/`, `frontend/`, `catalogs/`, `docs/`, `agent-rust/`.
- [x] A2 Stack levantado en limpio (`down -v` + `up --build`) y healthchecks OK.
- [x] A3 Estado git verificado limpio y sin PDFs trackeados en la comprobacion inicial.

### B) Calidad de codigo
- [x] B4 Lint (`ruff` + `mypy`) ejecutado y en verde.
- [x] B5 Tests ejecutados y en verde.
- [x] B6 Skips analizados y documentados.

### C) Funcionalidad end-to-end (1 click)
- [x] C7 Ejecutado: migrate + seed + demo-audit.
- [x] C8 Validado: `AuditRun` creado, estados `queued -> running -> completed`, findings/tareas generadas, reporte HTML/PDF generado.
- [x] C9 Evidencia de PDF en MinIO + descarga por `/evidence/{id}/download` + cabecera `%PDF`.

### D) Multi-tenant + RBAC (critico)
- [x] D10 Validado aislamiento tenant con 2 orgs/2 users y respuestas 403/404 cruzadas.
- [x] D11 RBAC validado para `org_admin`, `auditor`, `client_viewer`.
- [x] D12 Tests de integracion anadidos para cubrir huecos.

### E) Audit log inmutable
- [x] E13 Validado trigger de append-only y coherencia de hash chain en DB.
- [x] E14 Test anadido para intento de UPDATE/DELETE y fallo.

### F) Seguridad minima
- [x] F15 Validado: `secret_ref` (sin columna de secreto plano), limite tamano upload, allowlist MIME, rate-limit sensible en `/audit-runs` y `/evidence/upload`.
- [x] F16 Tests de seguridad anadidos (MIME/tamano/rate-limit).

### G) Documentacion
- [x] G17 `docs/architecture.md` existe y actualizado con decisiones reales.
- [x] G18 Documentacion incluye: como arrancar, demo, y fase 2 (`docs/runbook.md` + arquitectura).

---

## 2) Comandos exactos ejecutados

Nota: `make` no esta instalado en este entorno PowerShell. Se ejecutaron equivalentes directos de `docker compose`.

```powershell
# A) Infra
docker compose down -v
docker compose up -d --build
docker compose ps
docker compose ps --format json
git status --porcelain
git ls-files | rg -i '\.pdf$'
Get-Content .gitignore

# B) Calidad
docker compose exec api uv run ruff check app tests
docker compose exec api uv run mypy
docker compose exec api uv run pytest -q

# C) E2E
docker compose exec api uv run alembic upgrade head
docker compose exec api uv run python -m app.scripts.seed_data
docker compose exec api uv run python -m app.scripts.demo_audit
docker compose exec postgres psql -U audity -d audity -c "SELECT ... FROM audit_runs ..."
docker compose exec postgres psql -U audity -d audity -c "SELECT ... FROM findings ..."
docker compose exec postgres psql -U audity -d audity -c "SELECT ... FROM remediation_tasks ..."
docker compose exec postgres psql -U audity -d audity -c "SELECT ... FROM evidence_items ..."
Invoke-RestMethod POST http://localhost:58000/auth/mock/login ...
Invoke-WebRequest GET http://localhost:58000/evidence/{id}/download ...
docker compose exec api uv run python -c "import boto3; head_object(...)"

# D) Tenant + RBAC
docker compose exec -T api uv run python -  # script de 2 orgs/2 users y validacion 403/404
docker compose exec -T api uv run python -  # script de RBAC por rol

# E) Audit log inmutable
docker compose exec postgres psql -U audity -d audity -c "SELECT tgname ... FROM pg_trigger ..."
docker compose exec postgres psql -U audity -d audity -c "WITH ordered AS (...) SELECT count(*) AS chain_breaks ..."
docker compose exec postgres psql -v ON_ERROR_STOP=1 -U audity -d audity -c "UPDATE audit_log_entries ..."
docker compose exec postgres psql -v ON_ERROR_STOP=1 -U audity -d audity -c "DELETE FROM audit_log_entries ..."

# F) Secrets
docker compose exec -T api uv run python -  # crea integration con secret_ref y valida respuesta
docker compose exec postgres psql -U audity -d audity -c "SELECT column_name FROM information_schema.columns WHERE table_name='integrations' ..."
docker compose exec postgres psql -U audity -d audity -c "SELECT id, provider, name, secret_ref, config_json FROM integrations ORDER BY created_at DESC LIMIT 1;"
```

---

## 3) Resultados (evidencia)

### A) Infra
- `docker compose up -d --build`: servicios arriba con estado healthy (api/postgres/minio/redis/temporal).
- `docker compose ps`: sin contenedores `unhealthy`.
- `git status --porcelain` (inicio): vacio.
- `git ls-files | rg -i '\.pdf$'`: `(no tracked pdf files)`.

### B) Calidad
- Lint: `All checks passed!` + `Success: no issues found in 4 source files`.
- Tests finales: `13 passed, 1 skipped, 5 warnings in 4.77s`.
- Skip detectado:
  - `tests/test_audit_log.py`: `append-only trigger is postgres-specific`.
  - Motivo: suite principal usa sqlite en tests unitarios.
  - Habilitacion real postgres: usar la validacion DB/integ ejecutada en esta acceptance (ver E13/E14).

### C) E2E (demo)
- Seed output:
  - `Org ID: 1650ba17-10cb-4f98-80da-ff3c2b81ff18`
  - `Project ID: cc161b48-9acf-4ed5-afe5-645545ae9218`
- Demo output:
  - `Audit run created: be6e6124-4dfd-4aa8-9166-4af6d0b33b34`
  - `Run status: queued -> running -> ... -> completed`
  - `Report downloaded: /tmp/report_demo.pdf (14944 bytes)`
  - `report_id=2faa9a36-401f-4a8b-8a27-7d7b2c6c9eba`
- DB:
  - `findings=6`, `remediation_tasks=6` para el run.
  - `evidence_items` contiene `report_html` y `report` enlazados.
- Endpoint download:
  - `GET /evidence/2faa.../download` -> archivo `14944` bytes.
  - primeros bytes: `%PDF`.
- MinIO:
  - `head_object` OK para key `reports/.../be6e6124-...b34.pdf`, `size=14944`, `content_type=application/pdf`.

### D) Multi-tenant + RBAC
- Aislamiento tenant (script runtime 2 orgs/2 users):
  - `GET /organizations/{org_b}/projects => 403`
  - `GET /projects/{project_b} => 404`
  - `GET /projects/{project_b}/audit-runs/{run_b} => 404`
  - `GET /evidence/{evidence_b}/download => 404`
- RBAC (script runtime):
  - `org_admin GET /audit-log => 200`
  - `auditor POST /projects/{id}/audit-runs => 200`
  - `auditor GET /audit-log => 403`
  - `client_viewer POST /projects/{id}/audit-runs => 403`
  - `client_viewer POST /projects/{id}/evidence/upload => 403`
- Tests integracion anadidos:
  - `backend/tests/test_multitenant_rbac.py`

### E) Audit log inmutable
- Trigger presente:
  - `trg_audit_log_no_update` en `audit_log_entries`.
- Inmutabilidad DB:
  - `UPDATE ... audit_log_entries` -> error `audit_log_entries is append-only` (exit code 1).
  - `DELETE ... audit_log_entries` -> error `audit_log_entries is append-only` (exit code 1).
- Hash chain:
  - SQL `chain_breaks = 0`.
- Test anadido:
  - `backend/tests/test_audit_log.py` (incluye intento UPDATE/DELETE y validacion de cadena).

### F) Seguridad minima
- Secrets:
  - Tabla `integrations` no tiene columna de secreto en claro; usa `secret_ref`.
  - Creacion de integration de prueba devuelve `secret_ref=GITHUB_TOKEN_ENV`.
- Uploads:
  - Limite tamano existente y validado por test.
  - Allowlist MIME implementada y validada por test (rechazo 415 para `application/x-msdownload`).
- Rate limit:
  - Aplicado en `POST /projects/{id}/audit-runs` y `POST /projects/{id}/evidence/upload`.
  - Validado por tests de seguridad (segundo request -> 429 al simular limite sensible=1).
- Tests anadidos:
  - `backend/tests/test_security.py`

### G) Documentacion
- `docs/architecture.md` actualizado con controles reales de seguridad.
- `docs/runbook.md` anadido con:
  - Como arrancar
  - Como ejecutar demo
  - Que queda para fase 2

---

## 4) Issues encontrados + fixes aplicados (con commits)

1. Falta de allowlist MIME en upload y ausencia de rate-limit sensible en `/evidence/upload`.
   - Riesgo: subida de tipos no esperados y endpoint sensible sin control equivalente a audit-runs.
   - Fix: validacion de `content_type` + `enforce_sensitive_limit(request)` en upload.
   - Commit: `1410b7e` (`fix: enforce secure evidence upload guardrails`)

2. Cobertura incompleta de QA para multi-tenant/RBAC y seguridad minima.
   - Riesgo: no habia evidencia automatizada suficiente para checklist critico.
   - Fix: tests de integracion para aislamiento tenant/RBAC y tests de seguridad MIME/tamano/rate-limit.
   - Commits:
     - `50756f4` (`fix: validate tenant isolation, rbac and audit-log integrity`)
     - `1410b7e` (tests seguridad)

3. Falta de documento operativo de arranque/demo/fase 2 en `docs/`.
   - Riesgo: aceptacion/release no reproducible por equipos nuevos.
   - Fix: `docs/runbook.md` + ajuste de arquitectura.
   - Commit: `14ccc2d` (`fix: document startup demo and phase-2 gaps`)

---

## 5) Estado final

**PASS**

Motivo: todos los puntos A->G fueron verificados con comandos reproducibles y evidencia; los huecos detectados se corrigieron con commits pequenos, y el estado final de calidad es verde (`13 passed, 1 skipped`).
