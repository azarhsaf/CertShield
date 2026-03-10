import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def test_ingest_and_dashboard_flow():
    client = TestClient(app)
    payload = json.loads(Path('fixtures/sample_scan.json').read_text())
    r = client.post('/api/v1/collector/ingest', headers={'Authorization': 'Bearer collector-dev-token'}, json=payload)
    assert r.status_code == 200

    lp = client.get('/login')
    csrf = lp.text.split('name="csrf_token" value="')[1].split('"')[0]
    login = client.post('/login', data={'username': 'admin', 'password': 'ChangeMeNow!', 'csrf_token': csrf}, follow_redirects=True)
    assert login.status_code == 200
    assert 'Dashboard' in login.text

    history = client.get('/history')
    assert 'Scan History' in history.text

    rep = client.get('/reports/1.json')
    assert rep.status_code == 200
    assert rep.json()['scan']['findings'] >= 1
