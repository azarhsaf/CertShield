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

## Phase 1 PKI Posture Management Release Notes

Version: **Phase 1 PKI Posture Management**

Release Summary:
- Added PKI Posture dashboard and scoring.
- Added PKI Health assessment for CA service, CA certificate, CRL, AIA, OCSP, issuance, template health, collector coverage, and recommendations.
- Added PKI Best Practice assessment for Root CA, Issuing CA, Templates, Lifecycle, Auditing, and Backup/Recovery controls.
- Improved ADCS vulnerability finding evidence, risk scoring, score breakdown, business impact, technical impact, and remediation guidance.
- Improved collector coverage visibility and data coverage matrix across posture, health, best practices, and settings pages.
- Added visible product build label: `CertShield PKI Posture Management · Build: Phase 1 Posture`.
- Added report JSON sections for `posture`, `health`, `best_practices`, `coverage`, and `remediation_priorities`.
- Preserved backward compatibility with older collector payloads and the existing broad enrollment fallback used by current labs.

## Product Pages
- `/` - Executive dashboard with Overall PKI Posture, PKI Health, Best Practice Score, Critical ADCS Findings, Expiring Certificates, and Collector Coverage.
- `/pki-posture` - Management and technical view of overall PKI risk, top risks, remediation priorities, and data coverage.
- `/pki-health` - Operational PKI health for CA services, CA certificates, CRL/AIA/OCSP, issuance, template health, and collector coverage.
- `/best-practices` - PKI governance and architecture checks grouped by Root CA, Issuing CA, Templates, Lifecycle, Auditing, and Backup/Recovery.
- `/findings` - ADCS Vulnerability Assessment with risk score, severity, confidence, evidence, business impact, technical impact, coverage state, and safe remediation guidance.

## Collector Optional Flags
The PowerShell collector remains read-only and supports optional safety/diagnostic flags:
- `-SkipIssued` - skip issued certificate enumeration.
- `-DebugPayload` - print JSON payload before sending.
- `-NoPost` - build the payload but do not send it.
- `-OutputJson <path>` - write the payload to a JSON file.
- `-SkipHealth` - mark health-adjacent CA metadata as not assessed.
- `-SkipAcl` - mark ACL metadata as not assessed.
- `-SkipCrl` - mark CRL metadata as not assessed.

## Phase 1.1 UI and Scoring Stabilization Release Notes

Release: **Phase 1.1 UI and Scoring Stabilization**

Changes:
- Improved UI layout with compact one-line desktop navigation, smaller cards, tighter table spacing, and responsive wrapping.
- Replaced raw JSON/Python-dict evidence on main pages with readable evidence rows and pills.
- Fixed PKI Health scoring to avoid false Healthy status when CRL, AIA, OCSP, CA certificate, or issuance data is missing.
- Added Limited Visibility handling and score caps when more than half of required checks are Not Assessed.
- Improved PKI Posture score penalties and score caps when Critical ADCS findings or broad enrollment/requester-controlled identity exposure are detected.
- Clarified ADCS issued certificate inventory versus network SSL/TLS scanning; TLS endpoint scanning is not configured in this phase.
- Improved CA inventory assessment coverage display with compact CRL, AIA, OCSP, web enrollment, CA policy, and CA role badges.
- Improved collector health coverage fields for CA certificate, CRL, AIA, OCSP, issued certificates, template ACL, and CA registry/config evidence.
- Added tests for PKI Health scoring, posture score caps, page rendering, no raw dict evidence on main pages, empty certificate collection guidance, and existing ingest compatibility.

## Version 0.3.0 Release Notes

Release date: 2026-06-07
Build: **Phase 1.1 UI and Scoring Stabilization**

What changed:
- Added visible app version/build labels in the footer and Settings page.
- Added a CA-agnostic collector contract with `collector_type` and `schema_version` so ADCS works now and EJBCA/generic collectors can be added later.
- Added PKI Hierarchy view for Root/Sub CA relationships, independent PKI groupings, validation paths, and key protection posture.
- Improved multi-CA ingest/display validation so multiple CAs in one scan are stored and shown together.
- Improved CRL/AIA/OCSP logic to use real collector evidence and avoid false Healthy states.
- Added key protection visibility for HSM/software/unknown CA keys.
- Redesigned Best Practices into high-level category cards, top gaps, and recommendations.
- Clarified issued certificate inventory versus future network TLS scanning.

Known limitations:
- ADCS collection remains read-only and best-effort; some CA registry, LDAP, or CRL reachability checks may require permissions or network access.
- OCSP is optional and may be shown as Not Configured / Not Assessed when no responder URL is present.
- EJBCA and TLS collectors are documented but not implemented in this release.

## Upgrade from GitHub

```bash
sudo ./scripts/upgrade_linux.sh
```

The upgrade script stops the service, backs up `.env` and SQLite databases to
`/opt/certshield-backups/<timestamp>/`, resets the working tree to `origin/main`,
updates the virtual environment, validates migrations, runs tests, restores
ownership, restarts the service, and checks `/health`.

Rollback notes:
- DB backups: `/opt/certshield-backups/<timestamp>/*.db`
- Environment backups: `/opt/certshield-backups/<timestamp>/.env`
- Code rollback example: `git reset --hard <previous-commit>` followed by service restart.

See `docs/collectors.md` for the normalized collector contract and
`collector/ejbca/README.md` for future EJBCA collector planning.

## Health Collection Notes

The PKI Health page now shows exactly where each health signal came from:

- **CA certificate health** is collected by the Windows collector with `certutil -config <CAHost\CAName> -ca.cert <file>`. If this is Not Assessed, run the collector without `-SkipHealth` from a domain-joined host that can query the CA.
- **CRL/CDP health** is extracted from the CA certificate CDP extension and `certutil -config <CAHost\CAName> -getreg CA\CRLPublicationURLs`. HTTP CRL URLs are fetched automatically and parsed for `thisUpdate` / `nextUpdate` when reachable. LDAP-only CDPs are displayed as present but not HTTP-tested.
- **AIA health** is extracted from the CA certificate AIA extension and `certutil -config <CAHost\CAName> -getreg CA\CACertPublicationURLs`. HTTP CA issuer URLs are probed automatically.
- **OCSP health** is extracted from OCSP URLs in the AIA extension. If no OCSP URL exists, CertShield shows Not Configured rather than Healthy. If an OCSP URL is present, the collector performs a safe HTTP endpoint reachability probe only; it does not submit OCSP validation requests.
- **Certificate issuance health** is collected per CA with `certutil -config <CAHost\CAName> -view -restrict "Disposition=20"`. The collector account must be allowed to read CA database/request rows. If the page shows zero rows, check the displayed collection reason and confirm the command works manually on the collector host.
