from app.models.entities import CertificateAuthority
from app.services.health_assessment import assess_pki_health


def test_missing_crl_aia_ocsp_and_ca_expiry_are_not_healthy_and_cap_visibility():
    ca = CertificateAuthority(name="Lab-CA", dns_name="ca.lab", status="online", config_json={})
    health = assess_pki_health([ca], [], [], [], "now", "test", "collector", {})

    by_category = {item["category"]: item for item in health["items"]}
    assert by_category["CA Certificate Health"]["status"] == "Not Assessed"
    assert by_category["CRL Health"]["status"] == "Not Assessed"
    assert by_category["AIA Health"]["status"] == "Not Assessed"
    assert by_category["OCSP Health"]["status"] == "Not Assessed"
    assert health["score"] <= 69
    assert health["limited_visibility"] is True


def test_crl_with_url_reachable_and_future_next_update_is_healthy():
    ca = CertificateAuthority(
        name="Healthy-CA",
        dns_name="ca.lab",
        status="online",
        config_json={
            "certificate_expires_at": "2030-01-01",
            "crl": {
                "assessed": True,
                "configured": True,
                "reachable": True,
                "urls": ["http://ca.lab/ca.crl"],
                "next_update": "2030-01-01",
            },
            "aia": {"assessed": True, "configured": True, "reachable": True, "urls": ["http://ca.lab/ca.crt"]},
            "ocsp": {"assessed": True, "configured": False, "urls": []},
        },
    )
    health = assess_pki_health([ca], [], [], [], "now", "test", "collector", {})
    by_category = {item["category"]: item for item in health["items"]}
    assert by_category["CRL Health"]["status"] == "Healthy"
    assert by_category["AIA Health"]["status"] == "Healthy"
    assert by_category["OCSP Health"]["status"] == "Not Configured"


def test_aia_present_not_tested_is_not_false_healthy_or_not_assessed():
    ca = CertificateAuthority(
        name="AIA-CA",
        dns_name="ca.lab",
        status="online",
        config_json={
            "certificate_expires_at": "2030-01-01",
            "crl": {"assessed": False},
            "aia": {"assessed": True, "configured": True, "reachable": None, "urls": ["http://ca.lab/ca.crt"]},
            "ocsp": {"assessed": False},
        },
    )
    health = assess_pki_health([ca], [], [], [], "now", "test", "collector", {})
    by_category = {item["category"]: item for item in health["items"]}
    assert by_category["AIA Health"]["status"] == "Present / Not Tested"
