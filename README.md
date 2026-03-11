# CertShield

CertShield is a **defensive ADCS visibility and misconfiguration assessment platform** for blue teams. The web app runs on Linux, while a Windows PowerShell collector gathers ADCS/AD metadata and securely pushes normalized scan payloads into CertShield.

> Recommended platform: **Rocky Linux 9**.
> 
> CentOS 7 is **not recommended** (Python 3.6, OpenSSL/toolchain age, dependency build friction).

## Phase 1 Features
- Linux-hosted FastAPI + Jinja UI with SQLite by default.
- Authenticated UI pages: login, dashboard, CA inventory, templates, findings, certificates, scan history, settings.
- Windows collector integration (`/api/v1/collector/ingest`) using bearer token.
- Defensive ADCS rules engine (ESC-style combinations, weak approval patterns, validity concerns, broad publication patterns).
- Scan history and exports (JSON + HTML report, browser print-to-PDF friendly).
- Health endpoint (`/health`).
- Deployment artifacts: systemd unit + nginx reverse proxy sample.

## Architecture
- **Linux app**: FastAPI + SQLAlchemy + SQLite.
- **Windows collector**: PowerShell 5.1 script using `certutil` + ActiveDirectory module.
- **Flow**:
  1. Collector gathers CA/template/request data.
  2. Collector posts JSON to Linux API.
  3. App stores scan, runs risk rules, renders findings/dashboard.

---

## Rocky Linux Prerequisites
Install base packages:

```bash
sudo dnf -y update
sudo dnf -y install git python3.11 python3.11-devel gcc openssl-devel libffi-devel
```

> If `python3.11` is not available from enabled repos, install it first from supported Rocky sources. Do not use Python 3.6.

## Python Requirement
- **Required**: Python **3.11+**.
- Verified and supported by project packaging and dependencies.

---

## Fresh Clone Install (Rocky Linux)
```bash
git clone <your-repo-url> CertShield
cd CertShield
./scripts/install_linux.sh
cp .env.example .env
```

Edit `.env` at minimum:
- `SECRET_KEY` (strong random value)
- `BOOTSTRAP_ADMIN_PASSWORD`
- `COLLECTOR_API_TOKEN`

## Virtualenv (manual equivalent)
```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e '.[dev]'
```

---

## Run in Development
```bash
source .venv/bin/activate
make dev
```

App binds by default to `0.0.0.0:8000`.

Open:
- `http://<server-ip>:8000/login`

Bootstrap admin behavior:
- On first startup, the app creates `BOOTSTRAP_ADMIN_USER`/`BOOTSTRAP_ADMIN_PASSWORD` if that user does not exist.

Optional demo seed:
```bash
make seed
```

---

## Run in Production
```bash
source .venv/bin/activate
make run
```

Environment variables used:
- `BIND_HOST` (default `0.0.0.0`)
- `BIND_PORT` (default `8000`)

### systemd Setup
1. Copy project to `/opt/certshield`.
2. Create service user:
   ```bash
   sudo useradd --system --create-home --shell /sbin/nologin certshield
   ```
3. Copy `systemd/certshield.service` to `/etc/systemd/system/certshield.service`.
4. Ensure `/opt/certshield/.env` exists.
5. Enable service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now certshield
   sudo systemctl status certshield
   ```

### Nginx Reverse Proxy
Use `deploy/nginx.conf` as baseline, then:
```bash
sudo cp deploy/nginx.conf /etc/nginx/conf.d/certshield.conf
sudo nginx -t
sudo systemctl enable --now nginx
sudo systemctl reload nginx
```

### firewalld
```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

---

## Windows Collector
File: `collector/windows/Collect-AdcsData.ps1`

### Prerequisites
- PowerShell **5.1**
- `certutil` available
- ActiveDirectory module (RSAT AD PowerShell tools)
- Domain-joined host recommended

### One-line connectivity/API ingest test
```powershell
powershell -ExecutionPolicy Bypass -Command "$b='{\"domain_name\":\"corp.local\",\"source_host\":\"testhost\",\"cas\":[],\"templates\":[],\"issued_certificates\":[]}'; Invoke-RestMethod -Method Post -Uri 'http://<linux-ip>:8000/api/v1/collector/ingest' -Headers @{Authorization='Bearer <TOKEN>'} -ContentType 'application/json' -Body $b"
```

### One-line collector run
```powershell
powershell -ExecutionPolicy Bypass -File .\collector\windows\Collect-AdcsData.ps1 -ApiUrl "http://<linux-ip>:8000" -ApiToken "<TOKEN>" -RecentRequestLimit 200
```

Optional switches:
- `-SkipIssued` to skip certutil request retrieval
- `-DebugPayload` to print JSON before POST

### Collector compatibility note
The collector intentionally includes the broad permission fallback:
- `Authenticated Users` with `can_enroll=true`

This preserves existing risk-engine behavior and finding visibility.

---

## Testing & Validation
```bash
make lint
make test
make migrate-check
python -m compileall app tests scripts
```

Health check:
```bash
curl -s http://127.0.0.1:8000/health
```

---

## Troubleshooting

### Python version mismatch / install fails
- Symptom: install errors on older Python.
- Fix: use Rocky Linux + Python 3.11+.

### bcrypt/passlib mismatch from older deployments
- CertShield now uses stdlib PBKDF2 password hashing to avoid passlib/bcrypt runtime mismatch.

### App only reachable on localhost
- Ensure bind host is `0.0.0.0` (`make dev` already does this).
- Confirm firewall/security groups allow inbound traffic.

### Missing ActiveDirectory module on Windows
- Install RSAT AD PowerShell tools.
- Re-run collector.

### HTTP 422 on ingest
- Indicates JSON schema mismatch.
- Use the provided collector script unchanged, or validate payload keys against `app/schemas/collector.py`.

### No findings showing
- Confirm collector token matches `.env`.
- Confirm templates are ingested.
- Risk rules depend on key template properties and enrollment fallback permissions; do not remove the default broad enrollment fallback unless you also change rules.

---

## Security Notes
- Change all defaults in `.env` before production.
- Use HTTPS at reverse proxy.
- Restrict collector token distribution and rotate regularly.
- Keep collector host access limited and monitored.

## Screenshots
After startup and ingest, capture UI states for your environment (login/dashboard/findings) and store under `docs/screenshots/` for internal runbooks.
