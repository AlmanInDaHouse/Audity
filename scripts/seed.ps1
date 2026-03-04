$ErrorActionPreference = 'Stop'

Write-Host 'Running: docker compose exec api uv run python -m app.scripts.seed_data'
docker compose exec api uv run python -m app.scripts.seed_data
