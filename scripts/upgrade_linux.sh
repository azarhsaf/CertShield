#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/certshield}"
SERVICE_NAME="${SERVICE_NAME:-certshield}"
BACKUP_DIR="${BACKUP_DIR:-/opt/certshield-backups/$(date +%Y%m%d-%H%M%S)}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8000/health}"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo ./scripts/upgrade_linux.sh" >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
cd "$APP_DIR"

echo "[CertShield] Stopping $SERVICE_NAME if present"
systemctl stop "$SERVICE_NAME" 2>/dev/null || true

echo "[CertShield] Backing up DB and .env to $BACKUP_DIR"
cp -a .env "$BACKUP_DIR/.env" 2>/dev/null || true
find . -maxdepth 1 -name '*.db' -exec cp -a {} "$BACKUP_DIR/" \; 2>/dev/null || true

echo "[CertShield] Updating from origin/main"
git fetch origin
git reset --hard origin/main

echo "[CertShield] Installing/updating Python environment"
python3.11 -m venv .venv 2>/dev/null || python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'

echo "[CertShield] Validating migrations and tests"
python scripts/validate_migrations.py
pytest -q
python -m ruff check app tests

echo "[CertShield] Restoring ownership"
chown -R certshield:certshield "$APP_DIR" 2>/dev/null || true

echo "[CertShield] Starting $SERVICE_NAME"
systemctl start "$SERVICE_NAME"
sleep 2
curl -fsS "$HEALTH_URL" || true

echo "[CertShield] Upgrade complete. Backups: $BACKUP_DIR"
