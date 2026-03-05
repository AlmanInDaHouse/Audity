# Audity Enterprise Runbook

## 1) Baseline Startup
### PowerShell (Windows)
1. `./scripts/dev_up.ps1`
2. `./scripts/dev_test.ps1`
3. `./scripts/demo_audit.ps1`

### Bash (Linux/macOS)
1. `./scripts/dev_up.sh`
2. `./scripts/dev_test.sh`
3. `./scripts/demo_audit.sh`

## 2) Manual Equivalent Commands
1. `docker compose down -v`
2. `docker compose up -d --build`
3. `docker compose exec api uv run alembic upgrade head`
4. `docker compose exec api uv run python -m app.scripts.seed_data`
5. `docker compose exec api uv run pytest -q tests`
6. `docker compose exec api uv run pytest -q tests_integration`
7. `docker compose exec api uv run python -m app.scripts.demo_audit`

## 3) Enterprise Profiles
- IdP: `docker compose --profile idp up -d keycloak`
- Vault: `docker compose --profile vault up -d vault`
- AV: `docker compose --profile av up -d clamav`
- Observability: `docker compose --profile obs up -d otel-collector prometheus loki grafana`
- Backup jobs: `docker compose --profile backup up -d postgres-backup minio-backup`
- WAF proxy: `docker compose --profile waf up -d waf`

## 4) Security Operations
### Secret management
1. Create secret reference:
   - `POST /organizations/{org_id}/secrets`
2. Rotate secret:
   - `POST /organizations/{org_id}/secrets/rotate`
3. Validate secret:
   - `POST /organizations/{org_id}/secrets/validate`

### SCIM provisioning
1. Create tenant SCIM token:
   - `POST /organizations/{org_id}/scim/tokens`
2. Provision users/groups:
   - `POST /scim/v2/Users`
   - `PATCH /scim/v2/Groups/{role}`

### MFA policy
1. Set security policy:
   - `PUT /organizations/{org_id}/security-policy`
2. Enforce for sensitive endpoints using `mfa=true` token claim.

## 5) Backup and Restore
### Backup
- PowerShell: `./scripts/backup.ps1`
- Bash: `./scripts/backup.sh`

### Restore
- PowerShell: `./scripts/restore.ps1 -BackupDir backups/<timestamp>`
- Bash: `./scripts/restore.sh backups/<timestamp>`

### Restore Smoke Check
1. API health: `GET /health`
2. Login + list projects for seeded org.
3. Run `demo_audit` and confirm status completes.

## 6) Reliability Exercises
### Load test (k6)
- `k6 run scripts/load_test.js -e ORG_ID=<org_id> -e PROJECT_ID=<project_id> -e BASE_URL=http://localhost:58000`

### Chaos-lite
- PowerShell: `./scripts/chaos_lite.ps1`
- Bash: `./scripts/chaos_lite.sh`

## 7) Incident Procedures
### Temporal down
1. Verify `temporal` container health.
2. Restart worker and temporal services.
3. Requeue failed runs if needed.

### Database restore
1. Stop API/worker writes.
2. Run restore script.
3. Apply migrations and run smoke checks.

### MinIO restore
1. Restore object backup.
2. Verify report/evidence downloads.
3. Validate signatures using `/evidence/{id}/verify-signature`.

## 8) SLO Baseline
- Availability target: 99.9% monthly.
- API p95 latency alert threshold: >1500ms sustained 15m.
- Error-rate alert threshold: >5% sustained 5m.
- Quarantine spike alert: abnormal increase in `audity_upload_quarantined_total`.

## 9) Remaining Items for Full Compliance/Legal Certification
- External legal review and signed DPA/SLA/Terms.
- Third-party pentest execution and formal attestation.
- SOC2/ISO certification process (this runbook only provides readiness kit artifacts).
