import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

COLLECTOR = Path('collector/windows/Collect-AdcsData.ps1').read_text()


def _ingest(client: TestClient, payload: dict) -> dict:
    response = client.post(
        '/api/v1/collector/ingest',
        headers={'Authorization': 'Bearer collector-dev-token-change-me'},
        json=payload,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _login(client: TestClient) -> None:
    page = client.get('/login')
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    client.post(
        '/login',
        data={'username': 'admin', 'password': 'ChangeMeNow!', 'csrf_token': csrf},
        follow_redirects=True,
    )


def test_collector_v18_contract_and_no_hardcoded_template_risk_defaults():
    assert "collector-ps51-1.8" in COLLECTOR
    assert '-OfflineCaMetadataPath' in COLLECTOR
    assert '-MaxIssuedCertificates' in COLLECTOR
    assert '-IncludeRevoked' in COLLECTOR
    assert '-SkipTemplateAcl' in COLLECTOR
    assert 'nTSecurityDescriptor' in COLLECTOR
    assert 'Convert-TemplateAcl' in COLLECTOR
    assert 'Convert-ADIntervalToDays' in COLLECTOR
    assert "validity_days = 365" not in COLLECTOR
    assert "principal = 'Authenticated Users'" not in COLLECTOR
    assert 'permissions_assessed = $false' in COLLECTOR
    assert 'acl_collection_reason' in COLLECTOR


def test_acl_not_hardcoded_and_broad_enrollment_requires_real_permission():
    base = {
        'collector_type': 'adcs',
        'schema_version': '1.2',
        'domain_name': 'acl.local',
        'source_host': 'collector01',
        'collector_version': 'collector-ps51-1.8',
        'cas': [],
        'issued_certificates': [],
        'health_coverage': {'template_acl_collected': False},
    }
    no_acl_payload = {
        **base,
        'templates': [
            {
                'name': 'NoAclUser',
                'display_name': 'No ACL User',
                'eku': ['Client Authentication'],
                'enrollee_supplies_subject': True,
                'manager_approval': False,
                'authorized_signatures': 0,
                'validity_days': 365,
                'renewal_days': 30,
                'published_to': [],
                'permissions': [],
                'raw': {'permissions_assessed': False, 'acl_collection_reason': 'access denied'},
            }
        ],
    }
    with TestClient(app) as client:
        result = _ingest(client, no_acl_payload)
        report = client.get(f"/reports/{result['scan_id']}.json").json()
        assert not any(f['category'] == 'ESC1-like' for f in report['findings'])

        broad_payload = json.loads(json.dumps(no_acl_payload))
        broad_payload['health_coverage']['template_acl_collected'] = True
        broad_payload['templates'][0]['name'] = 'BroadUser'
        broad_payload['templates'][0]['permissions'] = [
            {'principal': 'Domain Users', 'can_enroll': True, 'can_autoenroll': False}
        ]
        broad_payload['templates'][0]['raw'] = {
            'permissions_assessed': True,
            'acl_collection_reason': 'nTSecurityDescriptor parsed from Active Directory',
        }
        result = _ingest(client, broad_payload)
        report = client.get(f"/reports/{result['scan_id']}.json").json()
        assert any(f['category'] == 'ESC1-like' for f in report['findings'])


def test_template_validity_missing_is_not_treated_as_pass_or_hardcoded():
    payload = {
        'collector_type': 'adcs',
        'schema_version': '1.2',
        'domain_name': 'validity.local',
        'source_host': 'collector01',
        'collector_version': 'collector-ps51-1.8',
        'cas': [],
        'templates': [
            {
                'name': 'NoValidityTemplate',
                'display_name': 'No Validity Template',
                'eku': [],
                'published_to': [],
                'permissions': [],
                'raw': {'validity_days_assessed': False},
            }
        ],
        'issued_certificates': [],
    }
    with TestClient(app) as client:
        _ingest(client, payload)
        _login(client)
        page = client.get('/best-practices')
        assert page.status_code == 200
        assert 'NoValidityTemplate' in page.text
        assert 'Not Assessed' in page.text
        assert 'Not collected' in page.text


def test_offline_root_metadata_and_provider_mapping_feed_ui():
    payload = {
        'collector_type': 'adcs',
        'schema_version': '1.2',
        'domain_name': 'offline.local',
        'source_host': 'collector01',
        'collector_version': 'collector-ps51-1.8',
        'cas': [
            {
                'name': 'OFFLINE-ROOT-CA-IR',
                'dns_name': '',
                'status': 'offline',
                'config': {
                    'offline': True,
                    'domain_joined': False,
                    'auditing_enabled': True,
                    'audit': {'auditing_enabled': True, 'audit_filter': 127, 'evidence': ['offline metadata']},
                    'ca_certificate': {
                        'collected': True,
                        'subject': 'CN=OFFLINE-ROOT-CA-IR',
                        'issuer': 'CN=OFFLINE-ROOT-CA-IR',
                        'thumbprint': 'AA',
                        'not_after': '2035-01-01T00:00:00',
                        'is_self_signed': True,
                    },
                    'key_protection': {
                        'provider': 'Utimaco SecurityServer CSP',
                        'provider_type': 'hsm',
                        'storage': 'hsm',
                        'hsm_detected': True,
                        'evidence': ['offline root metadata file'],
                    },
                },
            }
        ],
        'templates': [],
        'issued_certificates': [],
        'health_coverage': {'audit_collected': True, 'key_protection_collected': True},
    }
    with TestClient(app) as client:
        _ingest(client, payload)
        _login(client)
        hierarchy = client.get('/pki-hierarchy').text
        practices = client.get('/best-practices').text
        assert 'HSM Protected' in hierarchy
        assert 'Utimaco SecurityServer CSP' in hierarchy
        assert 'Root CA detected' in practices
        assert 'Not Assessed - collector did not collect CA AuditFilter yet' not in practices


def test_key_protection_mapping_supports_hsm_software_unknown_provider_and_not_assessed():
    from app.services.pki_hierarchy import key_protection

    assert key_protection({'key_protection': {'provider': 'Utimaco SecurityServer CSP'}})['status'] == 'HSM Protected'
    assert key_protection({'key_protection': {'provider': 'Microsoft Software Key Storage Provider'}})['status'] == 'Software Key'
    assert key_protection({'key_protection': {'provider': 'Contoso Custom Provider', 'storage': 'unknown_provider'}})['status'] == 'Unknown Provider'
    assert key_protection({'key_protection': {'storage': 'not_assessed'}})['status'] == 'Not Assessed'
