# CertShield (Phase 1)

CertShield is a Linux-hosted defensive ADCS visibility platform for blue teams. It ingests ADCS/AD inventory from a Windows collector, stores scan history in SQLite, applies defensive risk rules (ESC-style exposure detection), and provides authenticated dashboards and exports.

## Features (Phase 1)
- FastAPI web app + server-rendered UI
- Windows PowerShell collector for ADCS/template enumeration
- Dashboard, CA inventory, template inventory, findings, issued certificates, scan history
- Risk engine with extensible rule objects
- Local history storage (SQLite)
- JSON + HTML report export (PDF-friendly via browser print-to-PDF)
- Authentication, CSRF token on login form, audit logs
- Health endpoint
- Systemd and Nginx deployment artifacts
- Unit + integration tests

## Quickstart (dev)
```bash
./scripts/install_linux.sh
cp .env.example .env
make dev
```
In another shell:
```bash
make seed
```
Login at `http://localhost:8000/login` with bootstrap credentials from `.env`.

## Production deployment
1. Create Linux user + app directory (`/opt/certshield`).
2. Copy source and `.env`.
3. `python3 -m venv /opt/certshield/.venv && source /opt/certshield/.venv/bin/activate && pip install -e .`
4. Install `systemd/certshield.service` and run `systemctl enable --now certshield`.
5. Apply reverse proxy config from `deploy/nginx.conf`.

## Windows collector
Use `collector/windows/Collect-AdcsData.ps1`:
```powershell
.\Collect-AdcsData.ps1 -ApiUrl "https://certshield.example.com" -ApiToken "<collector token>"
```
Least privilege guidance:
- Read access to AD certificate template objects
- Read access to CA config/request metadata
- No enrollment/issuance/admin permissions required

## Testing
```bash
make lint
make test
python scripts/validate_migrations.py
```

## Hardening notes
- Change all default secrets and bootstrap password.
- Use HTTPS only behind reverse proxy.
- Restrict collector API token distribution and rotate periodically.
- Limit access to collector execution host.

## Troubleshooting
- Login fails: verify `.env` bootstrap credentials and restart service.
- No data on dashboard: run collector and confirm `/api/v1/collector/ingest` returns 200.
- SQLite locked: ensure single writer workload or move to Postgres in future phase.

## Future-ready design
- Risk rules live in `app/services/risk_engine.py` for easy expansion.
- Ingest abstraction in `app/services/ingest.py` supports scheduled scan runner later.
- Data model supports multi-scan historical analytics and upcoming RBAC extensions.
