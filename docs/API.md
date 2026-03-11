# CertShield API

## Health
### `GET /health`
Returns app health and runtime environment data.

## Collector ingest
### `POST /api/v1/collector/ingest`
Ingest Windows-collected ADCS inventory data.

Authentication:
- Header: `Authorization: Bearer <COLLECTOR_API_TOKEN>`

Payload schema:
- `domain_name` (string)
- `source_host` (string)
- `cas` (array)
- `templates` (array)
- `issued_certificates` (array)

Response:
```json
{"status":"ok","scan_id":1}
```

422 response indicates schema mismatch; use provided collector script to avoid payload drift.
