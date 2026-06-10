# CertShield Current Stable State

## Release

- Application version: 0.4.2
- Windows collector: collector-ps51-1.8.5

## Collector fixes

- Full AD certificate-template enumeration through DirectorySearcher.
- Template DACL and owner parsing from nTSecurityDescriptor.
- No hardcoded template ACL, validity, renewal, or risk values.
- Published-template fallback is used only when full AD enumeration returns zero.
- CA certificate fallback through AD cACertificate, local certificate stores, and supplied files.
- CSP/KSP provider parsing supports software and HSM providers.
- AuditFilter parsing supports decimal, hexadecimal, and certutil registry output.
- Missing AuditFilter on a reachable CA is classified as auditing not configured, not missing evidence.
- Offline metadata can provide verified audit and key-protection evidence for unreachable CAs.

## Application fixes

- Evidence gaps grouped by templates, CAs, and other controls.
- Template evidence gaps grouped by the actual template inventory.
- CA evidence gaps grouped by the actual CA inventory.
- Template ownership represented as one governance gap for published templates.
- Duplicate CA auditing and key-protection registry records removed.
- Best practices recalculated when posture is refreshed.
- Evidence-gap and posture pages handle incomplete or legacy scan data.
- Template risk rendering handles missing issue collections safely.

## Installation

- Interactive installer supports upgrade and clean-install modes.
- Upgrade preserves the existing database and environment.
- Clean install removes existing application data only after explicit selection.

## Required validation

Run before every pull request:

    pytest -q
    python -m ruff check app tests

Never commit:

- .env
- .venv/
- certshield.db
- __pycache__/
- credentials, API tokens, certificates, or private keys
