# API Endpoints

## `POST /api/v1/collector/ingest`
Bearer token auth using `COLLECTOR_API_TOKEN`.

Payload schema:
- `domain_name`
- `source_host`
- `cas[]`
- `templates[]`
- `issued_certificates[]`

Returns: `{ "status": "ok", "scan_id": <int> }`

## `GET /health`
Readiness/health check.

## `GET /reports/{scan_id}.json`
Authenticated export of normalized summary + findings.
