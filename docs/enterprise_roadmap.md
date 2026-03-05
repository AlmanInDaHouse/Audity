# Enterprise Hardening Plan

## Goal
Evolve Audity from MVP to enterprise-ready with phased delivery, feature flags, reproducible operations, and hard multi-tenant controls.

## Phase 0 Baseline (implemented now)

### Epics
1. Reproducible developer operations.
2. Enterprise roadmap, risk register, acceptance evidence framework.
3. CI baseline preserving `demo-audit`.

### Stories + Acceptance Criteria
1. As an engineer, I can run `scripts/dev_up.ps1` or `scripts/dev_up.sh` and get a clean stack ready for demo/testing.
   - AC: `docker compose down -v && up --build && alembic upgrade head && seed` succeeds.
2. As a release manager, I can run `scripts/dev_test.*` and execute lint + unit + integration tests.
   - AC: command exits `0`, with unit/integration/e2e checks.
3. As a stakeholder, I can inspect enterprise plan and acceptance evidence in docs.
   - AC: this document + `enterprise_acceptance_report.md` exist and are versioned.

### Dependencies
- Docker Desktop with compose.
- Python environment in API/worker images.
- Postgres/Redis/MinIO/Temporal healthy.

### Risks
- Local environment resource contention.
- Profile sprawl in compose if not documented.

## Phase 1 Blockers (implemented end-to-end)

### Epic 1: Enterprise Auth (OIDC/SAML-ready + SCIM + MFA + revocation)
Stories:
1. OIDC token validation via JWKS with issuer/audience checks.
2. Refresh token sessions with rotation and logout revocation.
3. MFA-sensitive guard on high-risk endpoints.
4. SCIM v2 Users/Groups provisioning with per-tenant bearer token.

Acceptance Criteria:
- `/auth/refresh` rotates session and returns new tokens.
- `/auth/logout` revokes refresh session.
- `POST /projects/{id}/audit-runs` and `POST /projects/{id}/evidence/upload` require MFA when org policy says so.
- `/scim/v2/Users` and `/scim/v2/Groups` support create/update/list with audit trail.

### Epic 2: Secret Management + Encryption
Stories:
1. `SecretStore` abstraction with `env` and `vault` drivers.
2. Integration payload blocks plaintext secret fields.
3. Secret rotation/validation endpoints for org admins.

Acceptance Criteria:
- Secrets can be set/get/rotate by `secret_ref`.
- DB stores references, not secret plaintext values.
- Vault profile can be enabled without app code changes.

### Epic 3: API Hardening + AV Quarantine
Stories:
1. Sensitive rate-limit keys include IP + user + org.
2. Upload size limits by org policy/pricing plan.
3. ClamAV scan result controls downloadability.
4. Quarantine metrics exported.

Acceptance Criteria:
- 429 generated on sensitive bursts.
- Upload rejects disallowed MIME and oversize by policy.
- Infected/scan-error evidence remains quarantined (`423` on download).

### Epic 4: Strong Traceability
Stories:
1. Evidence/report manifest generation.
2. Signature bundle generation and verification endpoint.
3. Retention metadata and immutable evidence versioning fields.

Acceptance Criteria:
- Evidence includes `manifest_json` and `signature_bundle_json`.
- Report signatures persisted in run metadata.
- `/evidence/{id}/verify-signature` verifies integrity.

### Epic 5: Operations Base (backup/restore + runbooks)
Stories:
1. Backup and restore scripts for Postgres and MinIO.
2. Profile-based periodic backup containers.
3. Incident runbook updates.

Acceptance Criteria:
- `scripts/backup.*` and `scripts/restore.*` available.
- `backup` compose profile provides recurring backup jobs.

## Phase 2 Reliability + Scale (implemented end-to-end)

### Epic 1: Observability
Stories:
1. Prometheus metrics endpoint and middleware instrumentation.
2. Optional OTel tracing for API/DB.
3. Local observability stack profile (`obs`) with Grafana dashboards.

Acceptance Criteria:
- `/metrics` exposes API latency/rate-limit/quarantine metrics.
- `obs` profile boots otel-collector + Prometheus + Grafana + Loki.
- Dashboard includes p95 latency, rate-limit hits, quarantined uploads.

### Epic 2: Resilience
Stories:
1. Temporal retry policies and worker concurrency tuning.
2. Load test script (`k6`) and chaos-lite restart script.

Acceptance Criteria:
- Retry policy configured in workflow activities.
- `scripts/load_test.js` and `scripts/chaos_lite.*` executable.

### Epic 3: Hard Multi-tenant (RLS)
Stories:
1. Postgres RLS policies for org-scoped tables.
2. `set_config('app.current_org_id', ...)` per authenticated request/session.

Acceptance Criteria:
- RLS policies applied in migration.
- API sets tenant context through dependency layer and workflow runtime.

### Epic 4: Release Quality
Stories:
1. CI executes lint + unit + integration + demo-e2e.
2. Versioning/changelog and rollback guidance documented.

Acceptance Criteria:
- GitHub workflow remains green with full stack checks.

## Phase 3 Product Enterprise (implemented product/tech)

### Epics
1. Advanced RBAC + ABAC.
2. Enterprise workflow approvals and waivers.
3. Outbound integrations framework (Jira/ServiceNow/SIEM stubs).
4. Auditor package one-click export.

### Acceptance Criteria
- Role permissions can be managed per org (`/organizations/{org_id}/permissions`).
- ABAC enforcement denies sensitive actions based on project tags/criticality.
- Approval + waiver endpoints available and audited.
- Export package endpoint produces signed evidence bundle zip.
- Outbound integration contracts available behind feature flags.

## Phase 4 Compliance + GTM Kit (implemented as kit/support)

### Epics
1. Internal compliance templates.
2. Legal/sales templates.
3. Pricing model and onboarding controls.

### Acceptance Criteria
- `/docs/compliance-kit/` and `/docs/legal-kit/` contain editable templates.
- Pricing plan endpoint + UI page provides module gating primitives.
- No hard claim of SOC2/ISO certification; only readiness kit.

## What Is Mandatory in Phase 1/2
- OIDC/SCIM/MFA/revocation controls implemented.
- SecretStore with Vault profile + plaintext prevention.
- AV quarantine + sensitive rate limits.
- Signature + retention metadata + verification.
- Observability metrics + stack profile.
- RLS + tenant context plumbing.
- CI automation and reproducible scripts.

## Known Remaining Risks
1. Production IdP federation (SAML brokering) requires environment-specific Keycloak/IdP setup.
2. Vault transit and external TSA providers are pluggable but require real credentials for production rollout.
3. Legal/compliance artifacts are templates and must be reviewed by counsel/compliance owners.
