param(
    [switch]$IncludeDemo
)

$ErrorActionPreference = 'Stop'

docker compose exec api uv run ruff check app tests tests_integration
docker compose exec api uv run mypy
docker compose exec api uv run pytest -q tests
docker compose exec api uv run pytest -q tests_integration

if ($IncludeDemo) {
    docker compose exec api uv run python -m app.scripts.demo_audit
}
