#!/usr/bin/env bash
set -euo pipefail

ts="$(date +%Y%m%d%H%M%S)"
backup_dir="backups/${ts}"
mkdir -p "${backup_dir}/minio"

docker compose exec -T postgres sh -c "pg_dump -U audity -d audity -F c" > "${backup_dir}/audity.dump"
docker run --rm --network audity_default -v "$(pwd)/${backup_dir}/minio:/backup" minio/mc:latest \
  sh -c "mc alias set src http://minio:9000 minioadmin minioadmin && mc mirror src/audity-evidence /backup"

echo "Backup completed: ${backup_dir}"
