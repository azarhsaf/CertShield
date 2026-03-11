import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def test_ingest_and_dashboard_flow():
    with TestClient(app) as client:
        payload = json.loads(Path('fixtures/sample_scan.json').read_text())
        payload['collector_version'] = 'legacy-test'

        r = client.post(
            '/api/v1/collector/ingest',
            headers={'Authorization': 'Bearer collector-dev-token-change-me'},
            json=payload,
        )
        if r.status_code == 401:
            r = client.post(
                '/api/v1/collector/ingest',
                headers={'Authorization': 'Bearer collector-dev-token'},
                json=payload,
            )
        assert r.status_code == 200

        lp = client.get('/login')
        csrf = lp.text.split('name="csrf_token" value="')[1].split('"')[0]
        login = client.post(
            '/login',
            data={'username': 'admin', 'password': 'ChangeMeNow!', 'csrf_token': csrf},
            follow_redirects=True,
        )
        assert login.status_code == 200
        assert 'PKI Dashboard' in login.text

        findings = client.get('/findings')
        assert 'Validate Exposure (Safe)' in findings.text

        rep = client.get('/reports/1.json')
        assert rep.status_code == 200
        assert 'coverage' in rep.json()
