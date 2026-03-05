# Audity Enterprise Architecture

## Scope
Audity is a multi-tenant audit platform with enterprise controls enabled by feature flags. The stack includes FastAPI, Temporal, Postgres, Redis, MinIO, and Next.js, with optional enterprise profiles for IdP, Vault, AV, observability, backup, and WAF.

## Core Components
- `backend/`: FastAPI API, RBAC/ABAC authorization, SCIM server endpoints, signing, reporting, package export.
- `worker/`: Temporal worker for audit workflows and heavy activities.
- `frontend/`: Next.js UI for audit runs and enterprise controls.
- `catalogs/`: versioned compliance catalogs and mappings.
- `infra/`: reverse proxy, Keycloak realm, observability configs, Nginx WAF profile.

## Multi-Tenant Model
- Tenant root: `Organization`.
- Data hierarchy: `Organization -> Project -> AuditRun -> Findings/Remediation/Evidence`.
- Application guardrails: every authenticated request sets `app.current_org_id` through dependency middleware.
- Database guardrails: PostgreSQL RLS policies on org-scoped tables.

## Auth and Identity
- Local/dev login: `/auth/mock/login` issuing JWT + refresh session.
- Enterprise OIDC: JWKS validation supported via `OIDC_JWKS_URL` + issuer/audience checks.
- Session security: refresh token rotation (`/auth/refresh`) and revocation (`/auth/logout`).
- MFA policy: org security policy (`require_mfa_sensitive`) and global flag can enforce `mfa=true` claim on sensitive endpoints.
- SCIM v2 server: `/scim/v2/Users`, `/scim/v2/Groups` with per-tenant bearer token managed by secret references.

## Secret Management
- `SecretStore` abstraction:
  - `env` backend for local/dev.
  - `vault` backend for enterprise profile.
- API stores references (`secret_ref`), not plaintext secrets.
- Integration config blocks common plaintext secret keys (`token`, `password`, `secret`, `private_key`).

## Data Integrity and Traceability
- Audit log remains append-only with hash chain.
- Evidence/report manifest + signature bundles (Ed25519) persisted in DB.
- Signature verification endpoint: `/evidence/{id}/verify-signature`.
- Retention and immutability metadata fields are stored on evidence rows.

## Upload and Malware Controls
- Strict MIME allowlist.
- Upload size governed by org security policy + pricing plan.
- SHA-256 computed on object write.
- ClamAV scan integration:
  - `clean`: downloadable.
  - `infected` or `scan_error`: quarantined (`423` on download).

## Observability
- Prometheus metrics endpoint `/metrics` with:
  - request counts and latency histogram.
  - rate-limit hit counters.
  - quarantined upload counters.
- Optional OpenTelemetry tracing for FastAPI + SQLAlchemy.
- `obs` profile: OTel collector, Prometheus, Grafana, Loki.

## Resilience and Scale
- Temporal activity retries and worker concurrency tuning.
- Load test script (`scripts/load_test.js`) and chaos-lite recovery script (`scripts/chaos_lite.*`).

## Enterprise Product Capabilities
- Advanced RBAC + ABAC with role-permission overrides.
- Approval/waiver flow for findings.
- Remediation comments.
- Outbound integration contract endpoints (Jira/ServiceNow/SIEM stubs).
- Auditor package export ZIP with evidence metadata/signatures.
- Pricing plan module gating (`/organizations/{org_id}/pricing-plan`).

## Profiles in Docker Compose
- `idp`: Keycloak dev IdP.
- `vault`: Hashicorp Vault dev server.
- `av`: ClamAV service.
- `obs`: OTel + Prometheus + Grafana + Loki.
- `backup`: recurring Postgres/MinIO backup jobs.
- `waf`: Nginx reverse proxy with baseline rules/headers.

## Security Baseline
- CORS controlled at API layer.
- Security headers middleware enabled.
- Global and sensitive rate limiting using Redis fallback memory limiter.
- Sensitive endpoints include org/user/IP in rate-limit keys.
- Feature-flag rollout for all enterprise capabilities.
