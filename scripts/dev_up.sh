#!/usr/bin/env bash
set -euo pipefail

use_ci_env="${1:-}"

if [[ ! -f .env ]]; then
  if [[ "$use_ci_env" == "--ci-env" && -f .env.ci ]]; then
    cp .env.ci .env
    echo "Created .env from .env.ci; edit if needed."
  elif [[ -f .env.example ]]; then
    cp .env.example .env
    echo "Created .env from .env.example; edit if needed."
  else
    echo "Missing .env.example and .env.ci; cannot bootstrap .env." >&2
    exit 1
  fi
fi

docker compose down -v || true
docker compose up -d --build
docker compose exec -T api uv run alembic upgrade head
docker compose exec -T api uv run python -m app.scripts.seed_data

echo "Dev stack ready."
