#!/usr/bin/env bash
set -euo pipefail
TOKEN=${COLLECTOR_API_TOKEN:-collector-dev-token}
curl -sS -X POST http://127.0.0.1:8000/api/v1/collector/ingest \
  -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  --data @fixtures/sample_scan.json
