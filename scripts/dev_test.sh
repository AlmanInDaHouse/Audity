#!/usr/bin/env bash
set -euo pipefail

include_demo="${1:-}"

docker compose exec -T api uv run ruff check app tests tests_integration
docker compose exec -T api uv run mypy
docker compose exec -T api uv run pytest -q tests
docker compose exec -T api uv run pytest -q tests_integration

if [[ "${include_demo}" == "--demo" ]]; then
  docker compose exec -T api uv run python -m app.scripts.demo_audit
fi
