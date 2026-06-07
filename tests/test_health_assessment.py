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
