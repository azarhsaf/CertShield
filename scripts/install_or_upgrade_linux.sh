#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/certshield"
REPO_URL="${REPO_URL:-https://github.com/azarhsaf/CertShield.git}"
SERVICE_NAME="${SERVICE_NAME:-certshield}"
BUILD_NAME_VALUE="Collector v1.8.1 - Template Fallback, Provider Parser, Risk Rendering Fix"
BUILD_LABEL_VALUE="Collector v1.8.1"

update_env_value() {
  local key="$1"
  local value="$2"
  local env_file="$APP_DIR/.env"

  touch "$env_file"
  if grep -q "^${key}=" "$env_file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$env_file"
  else
    echo "${key}=${value}" >> "$env_file"
  fi
}

install_deps() {
  cd "$APP_DIR"
  if [ ! -d ".venv" ]; then
    python3.12 -m venv .venv || python3 -m venv .venv
  fi
  source .venv/bin/activate
  python -m pip install --upgrade pip
  if [ -f "pyproject.toml" ]; then
    pip install -e ".[dev]" || pip install -e .
  else
    pip install fastapi uvicorn jinja2 python-multipart itsdangerous sqlalchemy pydantic pytest httpx ruff
  fi
}

restart_service() {
  chown -R certshield:certshield "$APP_DIR" 2>/dev/null || true
  systemctl restart "$SERVICE_NAME" 2>/dev/null || true
}

run_upgrade() {
  echo "[CertShield] Upgrade only selected. Existing data will be preserved."
  cd "$APP_DIR"
  git fetch origin
  git pull --rebase origin main
  update_env_value "BUILD_NAME" "$BUILD_NAME_VALUE"
  update_env_value "BUILD_LABEL" "$BUILD_LABEL_VALUE"
  install_deps
  restart_service
  echo "[CertShield] Upgrade completed."
}

run_clean_install() {
  echo "WARNING: Clean install will delete $APP_DIR including old database/data."
  echo "Type WIPE to continue:"
  read -r confirm
  if [ "$confirm" != "WIPE" ]; then
    echo "[CertShield] Clean install cancelled."
    exit 1
  fi

  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  rm -rf "$APP_DIR"
  git clone "$REPO_URL" "$APP_DIR"
  update_env_value "BUILD_NAME" "$BUILD_NAME_VALUE"
  update_env_value "BUILD_LABEL" "$BUILD_LABEL_VALUE"
  install_deps
  restart_service
  echo "[CertShield] Clean install completed."
}

echo "CertShield install/upgrade"
echo "1) Clean install - wipes existing app and data"
echo "2) Upgrade only - preserves existing data"
echo "3) Cancel"
read -r -p "Choose option [1-3]: " choice

case "$choice" in
  1) run_clean_install ;;
  2) run_upgrade ;;
  3) echo "[CertShield] Cancelled."; exit 0 ;;
  *) echo "Invalid option."; exit 1 ;;
esac
