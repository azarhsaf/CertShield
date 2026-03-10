.PHONY: dev test lint run seed

dev:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8000

seed:
	./scripts/seed_demo_scan.sh

test:
	pytest -q

lint:
	ruff check app tests
