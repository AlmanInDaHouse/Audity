$ErrorActionPreference = 'Stop'

Write-Host 'Running chaos-lite: restart worker and api, verify health recovers.'
docker compose kill worker
Start-Sleep -Seconds 3
docker compose up -d worker

docker compose kill api
Start-Sleep -Seconds 3
docker compose up -d api

for ($i = 0; $i -lt 20; $i++) {
    try {
        $resp = Invoke-RestMethod -Uri 'http://localhost:58000/health' -Method Get -TimeoutSec 3
        if ($resp.status -eq 'ok') {
            Write-Host 'API recovered.'
            exit 0
        }
    } catch {}
    Start-Sleep -Seconds 2
}

throw 'API did not recover in expected time window.'
