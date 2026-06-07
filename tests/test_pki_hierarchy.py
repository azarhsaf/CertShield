from app.models.entities import CertificateAuthority
from app.services.pki_hierarchy import build_pki_hierarchy, key_protection


def test_multiple_hierarchies_group_root_and_issuing_cas():
    root = CertificateAuthority(
        name="RootA",
        dns_name="roota.lab",
        status="online",
        config_json={"ca_type": "root", "ca_certificate": {"subject": "CN=RootA", "issuer": "CN=RootA"}},
    )
    issuing1 = CertificateAuthority(
        name="IssuingA1",
        dns_name="a1.lab",
        status="online",
        config_json={"ca_type": "issuing", "ca_certificate": {"subject": "CN=IssuingA1", "issuer": "CN=RootA"}},
    )
    issuing2 = CertificateAuthority(
        name="IssuingA2",
        dns_name="a2.lab",
        status="online",
        config_json={"ca_type": "issuing", "ca_certificate": {"subject": "CN=IssuingA2", "issuer": "CN=RootA"}},
    )
    independent = CertificateAuthority(
        name="IndependentRoot",
        dns_name="rootb.lab",
        status="offline",
        config_json={"ca_type": "root", "ca_certificate": {"subject": "CN=RootB", "issuer": "CN=RootB"}},
    )
    hierarchy = build_pki_hierarchy([root, issuing1, issuing2, independent], {}, {})
    assert hierarchy["ca_count"] == 4
    assert hierarchy["independent_hierarchies"] == 2
    first_root = hierarchy["hierarchies"][0]["root"]
    assert len(first_root["children"]) == 2


def test_key_protection_helper_classifies_provider_names():
    assert key_protection({"key_protection": {"provider": "Thales Luna KSP"}})["status"] == "HSM Protected"
    assert key_protection({"key_protection": {"provider": "Microsoft Software Key Storage Provider"}})["status"] == "Software Key"
