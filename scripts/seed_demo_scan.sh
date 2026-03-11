#!/usr/bin/env bash
set -euo pipefail
TOKEN=${COLLECTOR_API_TOKEN:-collector-dev-token-change-me}
BASE_URL=${BASE_URL:-http://127.0.0.1:8000}
curl -sS -X POST "${BASE_URL}/api/v1/collector/ingest" \
  -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  --data @fixtures/sample_scan.json
