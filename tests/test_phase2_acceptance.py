import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def _login(client: TestClient) -> str:
    page = client.get('/login')
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    client.post(
        '/login',
        data={'username': 'admin', 'password': 'ChangeMeNow!', 'csrf_token': csrf},
        follow_redirects=True,
    )
    return csrf


def test_risk_acceptance_reflects_across_pages_and_report():
    with TestClient(app) as client:
        payload = json.loads(Path('fixtures/sample_scan.json').read_text())
        payload['collector_version'] = 'collector-ps51-1.8'
        payload['schema_version'] = '1.2'
        response = client.post(
            '/api/v1/collector/ingest',
            headers={'Authorization': 'Bearer collector-dev-token-change-me'},
            json=payload,
        )
        assert response.status_code == 200
        scan_id = response.json()['scan_id']
        _login(client)
        findings = client.get('/findings')
        assert 'Accept Risk' in findings.text
        csrf = findings.text.split('name="csrf_token" value="')[1].split('"')[0]
        finding_id = re.search(r'/findings/(\d+)/accept', findings.text).group(1)
        accepted = client.post(
            f'/findings/{finding_id}/accept',
            data={
                'csrf_token': csrf,
                'expiry_date': '2099-01-01',
                'business_justification': 'Customer-approved lab policy exception.',
                'compensating_control': 'Restricted lab network and monitoring.',
                'scope': 'future_matching_fingerprint',
            },
            follow_redirects=True,
        )
        assert accepted.status_code == 200
        assert 'Accepted Risk' in accepted.text
        dashboard = client.get('/')
        assert 'PKI Assurance Level' in dashboard.text
        assert 'Accepted Risks' in dashboard.text
        assert 'Customer Policy Exception' in client.get('/templates').text
        assert 'Accepted Risk' in client.get('/best-practices').text
        posture = client.get('/pki-posture')
        assert 'Accepted Risk' in posture.text or 'Accepted' in posture.text
        report = client.get(f'/reports/{scan_id}.json').json()
        assert report['accepted_risks']
        assert any(item['accepted_risk'] for item in report['findings'])


def test_upgrade_and_fresh_install_scripts_are_executable():
    assert Path('scripts/upgrade_linux.sh').exists()
    assert Path('scripts/fresh_install_linux.sh').exists()
    assert Path('scripts/upgrade_linux.sh').stat().st_mode & 0o111
    assert Path('scripts/fresh_install_linux.sh').stat().st_mode & 0o111


def test_collector_version_and_schema_are_phase2():
    collector = Path('collector/windows/Collect-AdcsData.ps1').read_text()
    assert "collector-ps51-1.8" in collector
    assert "schema_version = '1.2'" in collector
    assert 'Get-EnrollmentServiceRecords' in collector
    assert 'Rejected truncated' in collector
