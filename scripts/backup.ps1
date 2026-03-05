$ErrorActionPreference = 'Stop'

$timestamp = Get-Date -Format 'yyyyMMddHHmmss'
$backupDir = "backups/$timestamp"
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null

Write-Host "Creating Postgres backup to $backupDir/audity.dump"
docker compose exec -T postgres sh -c "pg_dump -U audity -d audity -F c" | Set-Content -Encoding Byte "$backupDir/audity.dump"

Write-Host "Exporting MinIO objects to $backupDir/minio"
New-Item -ItemType Directory -Force -Path "$backupDir/minio" | Out-Null
docker run --rm --network audity_default -v "${PWD}\$backupDir\minio:/backup" minio/mc:latest sh -c "mc alias set src http://minio:9000 minioadmin minioadmin && mc mirror src/audity-evidence /backup"

Write-Host "Backup completed: $backupDir"
