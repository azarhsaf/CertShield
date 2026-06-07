# CertShield API

## Health
`GET /health`

Application liveness/readiness endpoint for reverse proxies and service monitors.

## Collector ingest
`POST /api/v1/collector/ingest`

Auth header:
`Authorization: Bearer <COLLECTOR_API_TOKEN>`

Required payload keys remain backward compatible with older collectors:
- `domain_name`
- `source_host`
- `cas[]`
- `templates[]`
- `issued_certificates[]`

Optional additive keys:
- `collector_version`
- `assessment_hints`
- additional CA `config` health/posture hints
- template `raw` ACL/owner metadata

Missing optional metadata is represented as `Not Assessed` or `Insufficient Data`; ingest should not fail.

## Report export
`GET /reports/{scan_id}.json`

The JSON report includes:
- `executive_summary`
- `posture`
- `health`
- `best_practices`
- `coverage`
- `remediation_priorities`
- `findings`

## Safe simulation view
`GET /findings/{finding_id}/simulate`

UI-only read-only exposure validation page. No certificate requests, credential use, relay workflows, or privilege-changing operations are performed.

## Collector schema version 1.1 additions

Collectors should include:
- `collector_type`: `adcs`, `ejbca`, `generic`, or future `tls`.
- `schema_version`: normalized payload version, currently `1.1`.
- `health_coverage`: booleans and errors describing whether CA certificate,
  CRL, AIA, OCSP, issued certificate, template ACL, and CA registry/config data
  were collected.

CA `config` may include normalized `ca_certificate`, `crl`, `aia`, `ocsp`, and
`key_protection` objects. Missing values should be represented as explicit
`configured=false`, `status=not_assessed`, or `reason` values instead of being
omitted.
