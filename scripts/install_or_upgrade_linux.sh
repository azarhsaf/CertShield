#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/certshield}"
REPO_URL="${REPO_URL:-https://github.com/azarhsaf/CertShield.git}"
SERVICE_NAME="${SERVICE_NAME:-certshield}"
BUILD_NAME_VALUE="Collector v1.8.1 - Template Fallback, Provider Parser, Risk Rendering Fix"
BUILD_LABEL_VALUE="Collector v1.8.1"

set_env_value() {
  local file="$1" key="$2" value="$3"
  touch "${file}"
  if grep -q "^${key}=" "${file}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${file}"
  else
    printf '\n%s=%s\n' "${key}" "${value}" >> "${file}"
  fi
}

stop_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "${SERVICE_NAME}" || true
  fi
}

restart_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart "${SERVICE_NAME}" || true
  fi
}

install_deps_and_validate() {
  cd "${APP_DIR}"
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
}

clean_install() {
  echo "WARNING: clean install will delete ${APP_DIR}, including certshield.db and local data."
  read -r -p "Type WIPE to continue: " confirmation
  if [ "${confirmation}" != "WIPE" ]; then
    echo "Clean install cancelled."
    exit 0
  fi
  stop_service
  rm -rf "${APP_DIR}"
  git clone "${REPO_URL}" "${APP_DIR}"
  cd "${APP_DIR}"
  cp .env.example .env
  set_env_value .env BUILD_NAME "${BUILD_NAME_VALUE}"
  set_env_value .env BUILD_LABEL "${BUILD_LABEL_VALUE}"
  install_deps_and_validate
  restart_service
  echo "Clean install complete at ${APP_DIR}."
}

upgrade_only() {
  if [ ! -d "${APP_DIR}/.git" ]; then
    echo "Cannot upgrade: ${APP_DIR} is not a git checkout."
    exit 1
  fi
  stop_service
  cd "${APP_DIR}"
  [ -f .env ] || cp .env.example .env
  cp -a .env ".env.pre-upgrade.$(date -u +%Y%m%dT%H%M%SZ)"
  git fetch origin main
  git reset --hard origin/main
  [ -f .env ] || cp .env.example .env
  set_env_value .env BUILD_NAME "${BUILD_NAME_VALUE}"
  set_env_value .env BUILD_LABEL "${BUILD_LABEL_VALUE}"
  install_deps_and_validate
  restart_service
  echo "Upgrade complete. Existing database and .env secrets were preserved."
}

cat <<MENU
CertShield install/upgrade
1) Clean install - wipes existing app and data under ${APP_DIR}
2) Upgrade only - preserves existing data and .env secrets
3) Cancel
MENU
read -r -p "Choose [1-3]: " choice
case "${choice}" in
  1) clean_install ;;
  2) upgrade_only ;;
  3) echo "Cancelled."; exit 0 ;;
  *) echo "Invalid choice."; exit 1 ;;
esac
