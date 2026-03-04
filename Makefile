PYTHON ?= python

.PHONY: up down logs lint test test-unit test-integration migrate seed fmt demo-audit ci

up:
	docker compose up -d --build

down:
	docker compose down -v

logs:
	docker compose logs -f --tail=150

migrate:
	docker compose exec api uv run alembic upgrade head

seed:
	docker compose exec api uv run python -m app.scripts.seed_data

lint:
	docker compose exec api uv run ruff check app tests tests_integration
	docker compose exec api uv run mypy

test-unit:
	$(MAKE) lint
	docker compose exec api uv run pytest -q tests

test-integration:
	docker compose exec api uv run pytest -q tests_integration

test: test-unit test-integration

demo-audit:
	docker compose exec api uv run python -m app.scripts.demo_audit

fmt:
	docker compose exec api uv run ruff format app tests tests_integration

ci:
	$(MAKE) up
	$(MAKE) migrate
	$(MAKE) seed
	$(MAKE) test
	$(MAKE) demo-audit
