param(
    [Parameter(Mandatory = $true)]
    [string]$BackupDir
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path "$BackupDir/audity.dump")) {
    throw "Missing $BackupDir/audity.dump"
}

Write-Host 'Restoring Postgres backup...'
Get-Content -Encoding Byte "$BackupDir/audity.dump" | docker compose exec -T postgres sh -c "pg_restore -U audity -d audity --clean --if-exists"

if (Test-Path "$BackupDir/minio") {
    Write-Host 'Restoring MinIO objects...'
    docker run --rm --network audity_default -v "${PWD}\$BackupDir\minio:/restore" minio/mc:latest sh -c "mc alias set dst http://minio:9000 minioadmin minioadmin && mc mirror --overwrite /restore dst/audity-evidence"
}

Write-Host 'Restore completed.'
