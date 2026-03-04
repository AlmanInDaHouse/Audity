param(
    [ValidateSet('unit', 'integration', 'all')]
    [string]$Scope = 'all'
)

$ErrorActionPreference = 'Stop'

function Run-Lint {
    Write-Host 'Running: docker compose exec api uv run ruff check app tests tests_integration'
    docker compose exec api uv run ruff check app tests tests_integration
    Write-Host 'Running: docker compose exec api uv run mypy'
    docker compose exec api uv run mypy
}

function Run-UnitTests {
    Write-Host 'Running: docker compose exec api uv run pytest -q tests'
    docker compose exec api uv run pytest -q tests
}

function Run-IntegrationTests {
    Write-Host 'Running: docker compose exec api uv run pytest -q tests_integration'
    docker compose exec api uv run pytest -q tests_integration
}

switch ($Scope) {
    'unit' {
        Run-Lint
        Run-UnitTests
    }
    'integration' {
        Run-IntegrationTests
    }
    'all' {
        Run-Lint
        Run-UnitTests
        Run-IntegrationTests
    }
}
