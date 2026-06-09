#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/certshield}"
SERVICE_NAME="${SERVICE_NAME:-certshield}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/certshield-backups}"
APP_URL="${APP_URL:-http://127.0.0.1:8000}"
HEALTH_URL="${HEALTH_URL:-${APP_URL}/health}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

rollback_hint() {
  echo "Rollback hint: cd ${APP_DIR} && sudo git reset --hard $(cat "${BACKUP_DIR}/git_commit.txt" 2>/dev/null || echo '<previous-commit>')"
  echo "Restore backups from: ${BACKUP_DIR}"
}

on_error() {
  echo "Upgrade failed before service restart. CertShield was not restarted into the failed release."
  rollback_hint
}
trap on_error ERR

cd "${APP_DIR}"
mkdir -p "${BACKUP_DIR}"
[ -f certshield.db ] && cp -a certshield.db "${BACKUP_DIR}/certshield.db"
[ -f .env ] && cp -a .env "${BACKUP_DIR}/.env"
git rev-parse HEAD > "${BACKUP_DIR}/git_commit.txt"

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop "${SERVICE_NAME}" || true
fi

git fetch origin main
git reset --hard origin/main

[ -f "${BACKUP_DIR}/.env" ] && cp -a "${BACKUP_DIR}/.env" .env
if [ ! -f .env ]; then
  cp .env.example .env
fi
ensure_env() {
  local key="$1" value="$2"
  if ! grep -q "^${key}=" .env; then
    printf '\n%s=%s\n' "${key}" "${value}" >> .env
  fi
}
ensure_env APP_VERSION "0.4.0"
ensure_env BUILD_NAME "Phase 2 - Scoring, Hierarchy, Collector Wiring, Risk Acceptance"
ensure_env BUILD_LABEL "Phase 2"
ensure_env COLLECTOR_API_TOKEN "$(openssl rand -hex 24 2>/dev/null || date +%s%N)"
ensure_env BOOTSTRAP_ADMIN_USER "admin"
ensure_env BOOTSTRAP_ADMIN_PASSWORD "ChangeMeNow!"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python scripts/validate_migrations.py
pytest -q
python -m ruff check app tests

trap - ERR
if id certshield >/dev/null 2>&1; then
  chown -R certshield:certshield "${APP_DIR}" "${BACKUP_DIR}" || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart "${SERVICE_NAME}"
fi

CURRENT_VERSION="$(python - <<'PY'
from app.core.config import get_settings
s=get_settings()
print(f'{s.app_version} / {s.build_name}')
PY
)"
CURRENT_COMMIT="$(git rev-parse --short HEAD)"
echo "CertShield upgraded successfully."
echo "Current version: ${CURRENT_VERSION}"
echo "Current commit: ${CURRENT_COMMIT}"
echo "App URL: ${APP_URL}"
echo "Health URL: ${HEALTH_URL}"
echo "Collector download path: ${APP_DIR}/collector/windows/Collect-AdcsData.ps1"
echo "Backup location: ${BACKUP_DIR}"
curl -fsS "${HEALTH_URL}" || true
