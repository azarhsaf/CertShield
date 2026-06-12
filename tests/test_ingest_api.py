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
        scan_id = r.json()["scan_id"]

        lp = client.get('/login')
        csrf = lp.text.split('name="csrf_token" value="')[1].split('"')[0]
        login = client.post(
            '/login',
            data={'username': 'admin', 'password': 'ChangeMeNow!', 'csrf_token': csrf},
            follow_redirects=True,
        )
        assert login.status_code == 200
        assert 'PKI Dashboard' in login.text
        assert 'CertShield PKI Posture Management' in login.text

        pages = (
            ('/pki-hierarchy', 'CA Inventory'),
            ('/pki-posture', 'Priority Actions'),
                ('/evidence-gaps', 'Evidence Gaps'),
            ('/pki-health', 'PKI Health'),
            ('/best-practices', 'Governance & Controls'),
            ('/reports', 'Reports'),
            ('/certificates', 'ADCS Issued Certificates / Requests'),
        )
        for path, text in pages:
            page = client.get(path)
            assert page.status_code == 200
            assert text in page.text
            assert "{'" not in page.text

        findings = client.get('/findings')
        assert 'Validate Exposure' in findings.text
        assert "{'" not in findings.text

        rep = client.get(f'/reports/{scan_id}.json')
        assert rep.status_code == 200
        report = rep.json()
        assert 'coverage' in report
        assert 'posture' in report
        assert 'health' in report
        assert 'best_practices' in report
        assert 'remediation_priorities' in report
        assert 'collector_coverage' in report
        assert 'health_issues' in report
        assert report['executive_summary']['pki_posture_score'] is not None
        assert report['executive_summary']['pki_posture_score'] <= 69

        hierarchy = client.get('/pki-hierarchy')
        assert 'CORP-ROOT-CA' in hierarchy.text
        assert 'CORP-ISSUING-02' in hierarchy.text
        assert 'LAB-ROOT-CA' in hierarchy.text
        assert 'PKI #1' in hierarchy.text
        assert 'PKI #2' in hierarchy.text
        assert 'http://ca02.corp.local/CertEnroll/CORP-ISSUING-02.crl' in hierarchy.text
        health_page = client.get('/pki-health')
        assert 'http://ca02.corp.local/CertEnroll/CORP-ISSUING-02.crl' in health_page.text


def test_certificates_page_explains_empty_collection():
    with TestClient(app) as client:
        payload = {
            'domain_name': 'empty.local',
            'source_host': 'collector02',
            'collector_version': 'legacy-empty',
            'cas': [{'name': 'EMPTY-CA', 'dns_name': 'ca.empty.local', 'status': 'online', 'config': {}}],
            'templates': [],
            'issued_certificates': [],
            'health_coverage': {'issued_certificates_collected': False, 'issued_certificates_reason': 'collector ran with SkipIssued'},
        }
        r = client.post(
            '/api/v1/collector/ingest',
            headers={'Authorization': 'Bearer collector-dev-token-change-me'},
            json=payload,
        )
        assert r.status_code == 200
        lp = client.get('/login')
        csrf = lp.text.split('name="csrf_token" value="')[1].split('"')[0]
        client.post(
            '/login',
            data={'username': 'admin', 'password': 'ChangeMeNow!', 'csrf_token': csrf},
            follow_redirects=True,
        )
        page = client.get('/certificates')
        assert page.status_code == 200
        assert 'Issued certificate data was not collected in the latest scan' in page.text
        assert 'Network TLS endpoint scanning is not configured in this phase' in page.text


def test_legacy_payload_without_health_coverage_still_ingests():
    with TestClient(app) as client:
        payload = {
            'domain_name': 'legacy.local',
            'source_host': 'legacy-collector',
            'collector_version': 'legacy',
            'cas': [{'name': 'LEGACY-CA', 'dns_name': 'ca.legacy.local', 'status': 'online', 'config': {}}],
            'templates': [
                {
                    'name': 'LegacyUser',
                    'display_name': 'Legacy User',
                    'eku': ['Client Authentication'],
                    'enrollee_supplies_subject': True,
                    'manager_approval': False,
                    'authorized_signatures': 0,
                    'validity_days': 365,
                    'renewal_days': 30,
                    'published_to': [],
                    'permissions': [
                        {'principal': 'Authenticated Users', 'can_enroll': True, 'can_autoenroll': False}
                    ],
                    'raw': {},
                }
            ],
            'issued_certificates': [],
        }
        r = client.post(
            '/api/v1/collector/ingest',
            headers={'Authorization': 'Bearer collector-dev-token-change-me'},
            json=payload,
        )
        assert r.status_code == 200
        assert r.json()['status'] == 'ok'
        lp = client.get('/login')
        csrf = lp.text.split('name="csrf_token" value="')[1].split('"')[0]
        client.post('/login', data={'username': 'admin', 'password': 'ChangeMeNow!', 'csrf_token': csrf}, follow_redirects=True)
        page = client.get('/pki-hierarchy')
        assert page.status_code == 200
        assert 'Unclassified CAs' in page.text
        assert 'LEGACY-CA' in page.text
        assert 'Unknown Root / External Root' not in page.text


def test_hierarchy_page_empty_db_does_not_crash():
    with TestClient(app) as client:
        lp = client.get('/login')
        csrf = lp.text.split('name="csrf_token" value="')[1].split('"')[0]
        client.post('/login', data={'username': 'admin', 'password': 'ChangeMeNow!', 'csrf_token': csrf}, follow_redirects=True)
        page = client.get('/pki-hierarchy')
        assert page.status_code == 200
        assert 'PKI Hierarchy' in page.text
