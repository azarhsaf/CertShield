# CertShield

CertShield is a **defensive ADCS exposure assessment and visibility** platform.
It helps blue teams inventory ADCS, identify risky certificate template and CA posture, and prioritize remediation.

## What CertShield Assesses
- Enterprise CAs and CA metadata
- Certificate templates, EKUs, and enrollment controls
- Enrollment permissions (including broad fallback compatibility)
- Issued certificate/request metadata where available
- Defensive ESC-style exposure categories (read-only assessment)
- Posture coverage state (`detected`, `not detected`, `not assessed`, `insufficient_data`)

## What CertShield Does NOT Do
- No exploitation
- No certificate abuse workflows
- No relay tooling
- No privilege escalation automation
- No spoofed SAN/UPN certificate requests

## Safe Simulation
CertShield includes **Validate Exposure (Safe)** views per finding. These dry-run views show preconditions met, missing evidence, possible impact, blast radius, confidence, and remediation that would break the exposure path.

They are intentionally read-only:
- No live requests
- No credentials used
- No privilege changes
- No attack execution
- No certificate enrollment or relay activity

## Supported Detection Categories (Defensive)
- ESC1-like: client-auth capable templates with requester-controlled subject/SAN, broad enrollment, and low/no approval safeguards.
- ESC2-like: Any Purpose / overly broad EKU semantics.
- ESC3-like: Enrollment Agent EKU exposure with dangerous enrollment access.
- ESC4-like: writable template object ACLs when collector-provided ACL metadata is available.
- ESC5-like: PKI object control paths when extended directory ACL metadata is available.
- ESC6-like: CA-level requester-supplied SAN policy exposure when CA policy flags are available.
- ESC7-like: dangerous CA management / approval role assignments when CA role metadata is available.
- ESC8-like: web enrollment / CES / CEP relay-prone posture when service metadata is available.
- Tier-0 posture: broad or risky PKI administration delegation when privileged access metadata is available.

## Platform
- Recommended: **Rocky Linux 9**
- Python **3.11+** required
- SQLite default supported

CentOS 7 is not recommended (older Python/OpenSSL/toolchain constraints).

## Quick Install (Fresh Clone)
```bash
git clone <repo-url> CertShield
cd CertShield
./scripts/install_linux.sh
cp .env.example .env
```

Edit `.env`:
- `SECRET_KEY`
- `BOOTSTRAP_ADMIN_PASSWORD`
- `COLLECTOR_API_TOKEN`

## Run
```bash
source .venv/bin/activate
make dev
```
Open: `http://<server-ip>:8000/login`

Bootstrap admin is auto-created on first startup from `.env` values.

## Production
- systemd unit: `systemd/certshield.service`
- reverse proxy sample: `deploy/nginx.conf`
- health endpoint: `/health`

## firewalld
```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

## Windows Collector
Script: `collector/windows/Collect-AdcsData.ps1`

### Prerequisites
- PowerShell 5.1
- `certutil`
- ActiveDirectory module / RSAT
- Domain-joined host recommended

### One-line run
```powershell
powershell -ExecutionPolicy Bypass -File .\collector\windows\Collect-AdcsData.ps1 -ApiUrl "http://<linux-ip>:8000" -ApiToken "<TOKEN>" -RecentRequestLimit 200
```

Optional:
- `-SkipIssued`
- `-DebugPayload`

The collector additively attempts to map templates published by Enterprise CAs via AD Enrollment Services objects. If AD metadata or RSAT is unavailable, CertShield marks the related categories as `not_assessed` or `insufficient_data` instead of failing ingestion.

### Backward Compatibility Note
Collector keeps the broad fallback permission for compatibility:
`Authenticated Users` + `can_enroll=true`.
This preserves current lab finding visibility.

## Confidence and Coverage States
- `detected`: evidence matched a defensive rule.
- `not_detected`: enough metadata was collected for that category and no exposure was found.
- `not_assessed`: collector did not attempt or could not collect required metadata.
- `insufficient_data`: some related data was present, but not enough to make a confident determination.

Confidence levels are conservative and reflect how direct the evidence is. For example, template EKU + permission evidence is higher confidence than posture hints that require richer CA or directory ACL data.

## Testing
```bash
make lint
make test
python scripts/validate_migrations.py
python -m compileall app tests scripts
```

## Troubleshooting
- **Python mismatch**: ensure Python 3.11+.
- **Bind/access issue**: run on `0.0.0.0` and check firewall.
- **Missing AD module**: install RSAT AD module.
- **HTTP 422 ingest**: payload schema mismatch; use bundled collector.
- **No findings**: confirm token matches and template data includes risky combinations.
- **Coverage shows not_assessed/insufficient_data**: collector needs richer metadata for those categories.

## Screenshots
Use Playwright or browser capture in your environment and store in `docs/screenshots/` for runbooks.
