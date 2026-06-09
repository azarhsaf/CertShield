# CertShield Collector Contract

CertShield is CA-agnostic PKI Posture Management. Collectors send a normalized,
read-only PKI inventory payload to the backend. Microsoft ADCS is supported now;
EJBCA and additional CA platforms can be added later by producing the same
contract.

## Required envelope

```json
{
  "collector_type": "adcs | ejbca | generic | tls",
  "schema_version": "1.2",
  "collector_version": "collector-specific-version",
  "source_host": "collector-hostname",
  "domain_name": "environment-name",
  "pki_system": "environment or CA platform name",
  "cas": [],
  "templates": [],
  "issued_certificates": [],
  "health_coverage": {},
  "assessment_hints": {}
}
```

## Normalized CA fields

Each CA should include stable identity and hierarchy evidence where available:

- `ca_id` if the collector has one.
- `name`, `dns_name`, `status`.
- `config.ca_type`: `root`, `issuing`, or `unknown`.
- `config.ca_certificate`: collected, error, subject, issuer, serial number,
  thumbprint, not_before, not_after, signature_algorithm, public_key_algorithm,
  key_size, subject_key_identifier, authority_key_identifier, is_self_signed,
  ca_role_hint, chain_complete.
- `config.crl`: configured, urls, http_urls, ldap_urls, file_urls, reachable,
  this_update, next_update, days_remaining, tested_urls, errors, source, reason.
- `config.aia`: configured, urls, ca_issuer_urls, ocsp_urls, reachable,
  tested_urls, errors, source.
- `config.ocsp`: configured, urls, reachable, status, errors.
- `config.key_protection`: provider, crypto_provider, provider_type,
  key_storage_provider, key_container, storage (`hsm`, `software`, `unknown`),
  hsm_detected, evidence.
- `config.published_templates`: templates/profiles published by the CA.

Missing evidence must be explicit: use `configured=false`, `status=not_assessed`,
or `reason="..."`; do not omit fields and rely on the backend to guess health.

## Platform-specific collectors

- `adcs`: PowerShell 5.1 collector using `certutil`, AD objects, and read-only
  certificate/registry queries.
- `ejbca`: future collector using EJBCA REST/API surfaces.
- `generic`: any CA platform that can produce the normalized schema.
- `tls`: future network TLS endpoint scanner; it should be separate from CA
  inventory collectors.


## Generic payload areas

Collectors should normalize platform data into `ca_list`/`cas`, `ca_certificate`, `crl`, `aia`, `ocsp`, `key_protection`, `profiles` or `templates`, `certificates`, and `health_evidence`/`health_coverage` sections. ADCS-specific ESC checks are evaluated only for ADCS collector payloads; generic PKI health and hierarchy logic should rely on the normalized fields above.
