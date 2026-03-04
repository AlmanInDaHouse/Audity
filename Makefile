PYTHON ?= python

.PHONY: up down logs lint test migrate seed fmt demo-audit

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
	docker compose exec api uv run ruff check app tests
	docker compose exec api uv run mypy

test:
	$(MAKE) lint
	docker compose exec api uv run pytest -q

demo-audit:
	docker compose exec api uv run python -m app.scripts.demo_audit

fmt:
	docker compose exec api uv run ruff format app tests
