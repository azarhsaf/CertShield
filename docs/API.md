# CertShield API

## Health
`GET /health`

## Collector ingest
`POST /api/v1/collector/ingest`

Auth header:
`Authorization: Bearer <COLLECTOR_API_TOKEN>`

Required payload keys:
- `domain_name`
- `source_host`
- `cas[]`
- `templates[]`
- `issued_certificates[]`

Optional additive keys:
- `collector_version`
- `assessment_hints`

## Report export
`GET /reports/{scan_id}.json`
- includes severity/category/confidence/coverage fields

## Safe simulation view
`GET /findings/{finding_id}/simulate`
- UI-only read-only exposure validation page
