#!/usr/bin/env bash
set -euo pipefail

docker compose kill worker || true
sleep 3
docker compose up -d worker

docker compose kill api || true
sleep 3
docker compose up -d api

for _ in $(seq 1 20); do
  if curl -fsS http://localhost:58000/health | grep -q '"ok"'; then
    echo "API recovered."
    exit 0
  fi
  sleep 2
done

echo "API did not recover in expected time."
exit 1
