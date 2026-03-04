param(
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'

$argsList = @('compose', 'up', '-d')
if (-not $NoBuild) {
    $argsList += '--build'
}

Write-Host "Running: docker $($argsList -join ' ')"
docker @argsList
