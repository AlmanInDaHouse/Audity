#!/usr/bin/env bash
set -euo pipefail

backup_dir="${1:?usage: scripts/restore.sh <backup-dir>}"

test -f "${backup_dir}/audity.dump"

cat "${backup_dir}/audity.dump" | docker compose exec -T postgres sh -c "pg_restore -U audity -d audity --clean --if-exists"

if [[ -d "${backup_dir}/minio" ]]; then
  docker run --rm --network audity_default -v "$(pwd)/${backup_dir}/minio:/restore" minio/mc:latest \
    sh -c "mc alias set dst http://minio:9000 minioadmin minioadmin && mc mirror --overwrite /restore dst/audity-evidence"
fi

echo "Restore completed from ${backup_dir}"
