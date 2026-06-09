from app.models.entities import CertificateAuthority
from app.services.best_practices import assess_best_practices


def test_key_protection_software_and_hsm_are_classified():
    software_root = CertificateAuthority(
        name="RootSoft",
        dns_name="root.lab",
        status="online",
        config_json={
            "ca_type": "root",
            "offline": False,
            "key_protection": {"provider": "Microsoft Software Key Storage Provider", "storage": "software", "hsm_detected": False},
        },
    )
    hsm_issuing = CertificateAuthority(
        name="IssuingHsm",
        dns_name="issuing.lab",
        status="online",
        config_json={
            "ca_type": "issuing",
            "installed_on_domain_controller": False,
            "key_protection": {"provider": "Thales Luna KSP", "storage": "hsm", "hsm_detected": True},
        },
    )
    result = assess_best_practices([software_root, hsm_issuing], [], [], [])
    key_items = [item for item in result["items"] if item["category"] == "Key Protection"]
    assert any(item["status"] == "Fail" and item["severity"] == "Critical" for item in key_items)
    assert any(item["status"] == "Pass" for item in key_items)
    assert result["summary_cards"]
