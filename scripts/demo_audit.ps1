$ErrorActionPreference = 'Stop'

$before = (git status --porcelain | Out-String).TrimEnd()
docker compose exec api uv run python -m app.scripts.demo_audit
$after = (git status --porcelain | Out-String).TrimEnd()

if ($before -ne $after) {
    Write-Error 'Repository changed after demo_audit run.'
    Write-Host '--- before ---'
    Write-Host $before
    Write-Host '--- after ---'
    Write-Host $after
    exit 1
}

Write-Host 'demo_audit completed with clean git status.'
