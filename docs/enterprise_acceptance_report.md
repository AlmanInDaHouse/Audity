# Enterprise Acceptance Report

## Date
- 2026-03-05

## Scope
- Implemented: Phase 0 baseline, Phase 1 enterprise blockers, Phase 2 reliability/scalability, Phase 3 product-tech capabilities.
- Delivered as kit/scaffold: Phase 4 compliance/legal/go-to-market documentation and pricing gates.

## 1) Reproducibility Commands

### Baseline startup/test/demo
```bash
docker compose down -v
docker compose up -d --build
docker compose exec api uv run alembic upgrade head
docker compose exec api uv run python -m app.scripts.seed_data
docker compose exec api uv run pytest -q tests
docker compose exec api uv run pytest -q tests_integration
docker compose exec api uv run python -m app.scripts.demo_audit
```

### New scripts
- PowerShell:
  - `scripts/dev_up.ps1`
  - `scripts/dev_test.ps1`
  - `scripts/demo_audit.ps1`
  - `scripts/backup.ps1`
  - `scripts/restore.ps1`
  - `scripts/chaos_lite.ps1`
- Bash:
  - `scripts/dev_up.sh`
  - `scripts/dev_test.sh`
  - `scripts/demo_audit.sh`
  - `scripts/backup.sh`
  - `scripts/restore.sh`
  - `scripts/chaos_lite.sh`

### Execution evidence in this environment
```text
python -m compileall app tests tests_integration
-> OK (all backend modules and tests compiled successfully)

docker compose down -v
-> FAILED: Docker Desktop engine not available
   error: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.
```

## 2) Phase 1 Checklist (Complete)

### Auth enterprise
- [x] OIDC JWT verification abstraction with JWKS support (`app/security.py`).
- [x] Refresh token rotation and revocation (`app/auth_sessions.py`, `/auth/refresh`, `/auth/logout`).
- [x] MFA policy enforcement on sensitive endpoints (`require_mfa`, org policy endpoint).
- [x] SCIM v2 Users/Groups provisioning endpoints and tenant token auth (`app/enterprise.py`).
- [x] Keycloak profile scaffolded in compose (`profile: idp`).

### Secret management
- [x] `SecretStore` abstraction with `env` and `vault` drivers (`app/secret_store.py`).
- [x] Secret set/rotate/validate endpoints.
- [x] Plaintext secret blocking in integration config payloads.
- [x] Vault profile scaffolded in compose (`profile: vault`).

### API hardening + uploads + AV
- [x] Sensitive rate-limit key expanded to IP + user + org.
- [x] Upload size limit derived from org policy + pricing plan.
- [x] MIME allowlist retained.
- [x] SHA-256 mandatory (existing store behavior retained).
- [x] AV scan integration with quarantine state and download block (`423`), ClamAV profile added (`profile: av`).

### Strong traceability
- [x] Evidence/report manifests signed (Ed25519).
- [x] Signature bundle persisted in evidence and run records.
- [x] Signature verification endpoint (`/evidence/{id}/verify-signature`).
- [x] Retention/immutable/version metadata fields added.

### Operations
- [x] Backup/restore scripts added (Postgres + MinIO).
- [x] Backup profile jobs added (`profile: backup`).
- [x] Runbook updated with incident/restore/SLO procedures.

## 3) Phase 2 Checklist (Complete)

### Observability
- [x] Prometheus metrics middleware and `/metrics`.
- [x] Optional OTel tracing setup for API + SQLAlchemy.
- [x] `obs` profile stack: otel-collector + Prometheus + Grafana + Loki.
- [x] Grafana dashboard provisioning (latency p95, rate-limit, quarantine counters).

### Scalability/resilience
- [x] Temporal retry policy + worker concurrency tuning.
- [x] Load test script (`scripts/load_test.js`).
- [x] Chaos-lite scripts for restart-recovery.

### Multi-tenant hardening (RLS)
- [x] Alembic migration adds RLS policies across org-scoped tables.
- [x] Request and workflow runtime set `app.current_org_id`.
- [x] Integration test added to validate DB-level cross-tenant block (`tests_integration/test_rls_enforcement.py`).

### Release quality
- [x] CI remains with lint + unit + integration + demo-e2e.
- [x] Nightly restore smoke workflow scaffolded (`nightly-restore-smoke.yml`).

## 4) Phase 3 Checklist (Product/Tech Implemented)

- [x] Advanced RBAC + ABAC engine (`app/permissions.py` + permission endpoints).
- [x] Finding approvals and waivers endpoints.
- [x] Remediation comments endpoints.
- [x] Outbound integrations contract API (Jira/ServiceNow/SIEM stubs).
- [x] Auditor package one-click export endpoint with ZIP artifacts/signatures.
- [x] Frontend enterprise page and package export button.

## 5) Phase 4 Checklist (Kit/Support Implemented)

- [x] Compliance kit templates (`docs/compliance-kit/`).
- [x] Legal kit templates (`docs/legal-kit/`).
- [x] Pentest and private bug bounty runbooks.
- [x] Pricing model endpoints + UI gate (`/pricing-plan`, `/enterprise` page).
- [x] Explicit non-claim of certification; readiness artifacts only.

## 6) Files Added/Updated (Key)
- Backend security and enterprise API:
  - `backend/app/enterprise.py`
  - `backend/app/secret_store.py`
  - `backend/app/auth_sessions.py`
  - `backend/app/permissions.py`
  - `backend/app/av_scanner.py`
  - `backend/app/signing.py`
  - `backend/app/telemetry.py`
  - `backend/app/otel.py`
  - `backend/app/package_export.py`
- Database migration:
  - `backend/alembic/versions/0002_enterprise_hardening.py`
- Infra profiles:
  - `docker-compose.yml`
  - `infra/keycloak/*`
  - `infra/nginx/*`
  - `infra/observability/*`
- Tests:
  - `backend/tests/test_enterprise_features.py`
  - `backend/tests_integration/test_rls_enforcement.py`
- Docs:
  - `docs/enterprise_roadmap.md`
  - `docs/architecture.md`
  - `docs/runbook.md`
  - `docs/compliance-kit/*`
  - `docs/legal-kit/*`

## 7) Final Status
- Code implementation: **COMPLETE for requested scope in-repo**, with Phase 4 as readiness kit.
- Runtime validation in this terminal: **PARTIAL**, blocked by unavailable Docker engine in this environment.
