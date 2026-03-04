$ErrorActionPreference = 'Stop'

$before = (git status --porcelain | Out-String).TrimEnd()

Write-Host 'Running: docker compose exec api uv run python -m app.scripts.demo_audit'
docker compose exec api uv run python -m app.scripts.demo_audit

$after = (git status --porcelain | Out-String).TrimEnd()
if ($before -ne $after) {
    Write-Error 'Repository status changed after demo_audit. Demo must not leave git artifacts.'
    Write-Host '--- Before ---'
    Write-Host $before
    Write-Host '--- After ---'
    Write-Host $after
    exit 1
}

Write-Host 'OK: git status unchanged after demo_audit.'
