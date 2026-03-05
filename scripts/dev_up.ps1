param(
    [switch]$UseCiEnv
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.env')) {
    if ($UseCiEnv -and (Test-Path '.env.ci')) {
        Copy-Item '.env.ci' '.env'
        Write-Host 'Created .env from .env.ci; edit if needed.'
    } elseif (Test-Path '.env.example') {
        Copy-Item '.env.example' '.env'
        Write-Host 'Created .env from .env.example; edit if needed.'
    } else {
        throw 'Missing .env.example and .env.ci; cannot bootstrap .env.'
    }
}

Write-Host 'Starting enterprise dev stack (default profile)...'
docker compose down -v
docker compose up -d --build
docker compose exec api uv run alembic upgrade head
docker compose exec api uv run python -m app.scripts.seed_data

Write-Host 'Dev stack ready.'
