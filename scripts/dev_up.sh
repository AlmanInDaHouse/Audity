#!/usr/bin/env bash
set -euo pipefail

docker compose down -v || true
docker compose up -d --build
docker compose exec -T api uv run alembic upgrade head
docker compose exec -T api uv run python -m app.scripts.seed_data

echo "Dev stack ready."
