#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/certshield}"
REPO_URL="${REPO_URL:-https://github.com/azarhsaf/CertShield.git}"
SERVICE_NAME="${SERVICE_NAME:-certshield}"

echo "Fresh lab install will reset ${APP_DIR}. Use upgrade_linux.sh for normal upgrades."
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop "${SERVICE_NAME}" || true
fi
rm -rf "${APP_DIR}"
git clone "${REPO_URL}" "${APP_DIR}"
cd "${APP_DIR}"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
cp .env.example .env
python scripts/validate_migrations.py
pytest -q
python -m ruff check app tests
if id certshield >/dev/null 2>&1; then
  chown -R certshield:certshield "${APP_DIR}" || true
fi
echo "Fresh lab install complete. Configure .env, install systemd unit if needed, then start CertShield."
