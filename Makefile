.PHONY: dev test lint run seed migrate-check

dev:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run:
	uvicorn app.main:app --host $${BIND_HOST:-0.0.0.0} --port $${BIND_PORT:-8000}

seed:
	./scripts/seed_demo_scan.sh

migrate-check:
	python scripts/validate_migrations.py

test:
	pytest -q

lint:
	ruff check app tests
