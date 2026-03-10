#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e '.[dev]'
if [ ! -f .env ]; then cp .env.example .env; fi
echo "Install complete. Edit .env then run: make run"
