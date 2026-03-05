$ErrorActionPreference = 'Stop'

Write-Host 'Starting enterprise dev stack (default profile)...'
docker compose down -v
docker compose up -d --build
docker compose exec api uv run alembic upgrade head
docker compose exec api uv run python -m app.scripts.seed_data

Write-Host 'Dev stack ready.'
