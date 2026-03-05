#!/usr/bin/env bash
set -euo pipefail

before="$(git status --porcelain)"
docker compose exec -T api uv run python -m app.scripts.demo_audit
after="$(git status --porcelain)"

if [[ "$before" != "$after" ]]; then
  echo "Repository changed after demo_audit."
  echo "--- before ---"
  echo "$before"
  echo "--- after ---"
  echo "$after"
  exit 1
fi

echo "demo_audit completed with clean git status."
