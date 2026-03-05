# Audity Enterprise Runbook

## Puertos
Puertos reales extraidos de `docker-compose.yml`.

| Servicio | Host -> Contenedor | Profile |
|---|---|---|
| Postgres | `55432 -> 5432` | default |
| Redis | `56379 -> 6379` | default |
| MinIO API | `59000 -> 9000` | default |
| MinIO Console | `59001 -> 9001` | default |
| Temporal | `57233 -> 7233` | default |
| API FastAPI | `58000 -> 8000` | default |
| Frontend Next.js | `53000 -> 3000` | default |
| Caddy HTTP | `5080 -> 80` | default |
| Caddy HTTPS | `5443 -> 443` | default |
| Keycloak | `58080 -> 8080` | `idp` |
| Vault | `58200 -> 8200` | `vault` |
| ClamAV | `53310 -> 3310` | `av` |
| OTel gRPC | `54317 -> 4317` | `obs` |
| OTel HTTP | `54318 -> 4318` | `obs` |
| Prometheus | `59090 -> 9090` | `obs` |
| Loki | `53100 -> 3100` | `obs` |
| Grafana | `53001 -> 3000` | `obs` |
| WAF Nginx | `5081 -> 80` | `waf` |

## Credenciales Demo

### Seed users (mock login)
No password required in MVP mock auth; login uses `email + org_id`.

- `admin@demo.local`
- `auditor@demo.local`
- `viewer@demo.local`

`org_id` and `project_id` are printed by:
```bash
docker compose exec api uv run python -m app.scripts.seed_data
```

### Infra default credentials
- MinIO: `minioadmin / minioadmin`
- Postgres: `audity / audity` (DB `audity`)
- Keycloak (`idp` profile): `admin / admin`
- Grafana (`obs` profile): `admin / admin`
- Vault (`vault` profile dev mode): token `root`

### Curl login example
```bash
curl -sS -X POST http://localhost:58000/auth/mock/login \
  -H 'content-type: application/json' \
  -d '{"email":"auditor@demo.local","org_id":"<ORG_ID>","mfa":true}'
```

## Demo en 5 minutos

1. Levantar stack y seed.
```bash
./scripts/dev_up.sh
# o PowerShell: .\scripts\dev_up.ps1
```

2. Login y obtener token.
```bash
TOKEN=$(curl -sS -X POST http://localhost:58000/auth/mock/login \
  -H 'content-type: application/json' \
  -d '{"email":"auditor@demo.local","org_id":"<ORG_ID>","mfa":true}' | jq -r .access_token)
```

3. Lanzar audit-run.
```bash
RUN_JSON=$(curl -sS -X POST http://localhost:58000/projects/<PROJECT_ID>/audit-runs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"catalog_version":"v1"}')
RUN_ID=$(echo "$RUN_JSON" | jq -r .id)
```

4. Polling hasta `completed`.
```bash
while true; do
  STATUS_JSON=$(curl -sS http://localhost:58000/projects/<PROJECT_ID>/audit-runs/$RUN_ID \
    -H "Authorization: Bearer $TOKEN")
  STATUS=$(echo "$STATUS_JSON" | jq -r .status)
  echo "run=$RUN_ID status=$STATUS"
  [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
  sleep 2
done
```

5. Descargar PDF y auditor package.
```bash
REPORT_ID=$(echo "$STATUS_JSON" | jq -r .report_evidence_id)
curl -sS http://localhost:58000/evidence/$REPORT_ID/download \
  -H "Authorization: Bearer $TOKEN" -o report.pdf

PKG_JSON=$(curl -sS -X POST \
  http://localhost:58000/projects/<PROJECT_ID>/audit-runs/$RUN_ID/export-package \
  -H "Authorization: Bearer $TOKEN")
PKG_EVIDENCE_ID=$(echo "$PKG_JSON" | jq -r .evidence_id)
curl -sS http://localhost:58000/evidence/$PKG_EVIDENCE_ID/download \
  -H "Authorization: Bearer $TOKEN" -o auditor-package.zip
```

## Baseline Startup
### PowerShell (Windows)
1. `./scripts/dev_up.ps1`
2. `./scripts/dev_test.ps1`
3. `./scripts/demo_audit.ps1`

### Bash (Linux/macOS)
1. `./scripts/dev_up.sh`
2. `./scripts/dev_test.sh`
3. `./scripts/demo_audit.sh`

## Manual Equivalent Commands
1. `docker compose down -v`
2. `docker compose up -d --build`
3. `docker compose exec api uv run alembic upgrade head`
4. `docker compose exec api uv run python -m app.scripts.seed_data`
5. `docker compose exec api uv run pytest -q tests`
6. `docker compose exec api uv run pytest -q tests_integration`
7. `docker compose exec api uv run python -m app.scripts.demo_audit`

## Enterprise Profiles
- IdP: `docker compose --profile idp up -d keycloak`
- Vault: `docker compose --profile vault up -d vault`
- AV: `docker compose --profile av up -d clamav`
- Observability: `docker compose --profile obs up -d otel-collector prometheus loki grafana`
- Backup jobs: `docker compose --profile backup up -d postgres-backup minio-backup`
- WAF proxy: `docker compose --profile waf up -d waf`

## Security Operations
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

## Backup and Restore
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

## Reliability Exercises
### Load test (k6)
- `k6 run scripts/load_test.js -e ORG_ID=<org_id> -e PROJECT_ID=<project_id> -e BASE_URL=http://localhost:58000`

### Chaos-lite
- PowerShell: `./scripts/chaos_lite.ps1`
- Bash: `./scripts/chaos_lite.sh`

## Incident Procedures
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

## SLO Baseline
- Availability target: 99.9% monthly.
- API p95 latency alert threshold: >1500ms sustained 15m.
- Error-rate alert threshold: >5% sustained 5m.
- Quarantine spike alert: abnormal increase in `audity_upload_quarantined_total`.

## Remaining Items for Full Compliance/Legal Certification
- External legal review and signed DPA/SLA/Terms.
- Third-party pentest execution and formal attestation.
- SOC2/ISO certification process (this runbook only provides readiness kit artifacts).
