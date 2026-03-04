$ErrorActionPreference = 'Stop'

Write-Host 'Running: docker compose exec api uv run alembic upgrade head'
docker compose exec api uv run alembic upgrade head
