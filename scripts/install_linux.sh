#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)'; then
  echo "Detected Python ${PYTHON_VERSION}"
else
  echo "Python 3.11+ is required. Detected ${PYTHON_VERSION}" >&2
  exit 1
fi

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e '.[dev]'

if [ ! -f .env ]; then
  cp .env.example .env
  echo ".env created from .env.example"
fi

echo "Install complete. Next: edit .env then run 'make dev'"
