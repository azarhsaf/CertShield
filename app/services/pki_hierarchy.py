from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.models.entities import CertificateAuthority

HSM_HINTS = ("nshield", "ncipher", "thales", "safenet", "luna", "utimaco", "fortanix", "azure key vault", "hsm")
SOFTWARE_HINTS = ("microsoft software", "software key", "strong cryptographic provider", "rsa#", "microsoft enhanced")


def _cfg(ca: CertificateAuthority) -> dict[str, Any]:
    return ca.config_json or {}


def ca_certificate(config: dict[str, Any]) -> dict[str, Any]:
    cert = config.get("ca_certificate") if isinstance(config.get("ca_certificate"), dict) else {}
    return {
        **cert,
        "subject": cert.get("subject") or config.get("certificate_subject") or config.get("subject"),
        "issuer": cert.get("issuer") or config.get("certificate_issuer") or config.get("issuer"),
        "serial_number": cert.get("serial_number") or config.get("serial_number"),
        "thumbprint": cert.get("thumbprint") or config.get("thumbprint"),
        "not_before": cert.get("not_before") or config.get("certificate_not_before"),
        "not_after": cert.get("not_after") or config.get("certificate_expires_at") or config.get("ca_certificate_expires_at"),
        "signature_algorithm": cert.get("signature_algorithm") or config.get("signature_algorithm"),
        "key_size": cert.get("key_size") or config.get("key_size"),
        "chain_complete": cert.get("chain_complete") if "chain_complete" in cert else config.get("chain_complete"),
    }


def ca_role(ca: CertificateAuthority) -> str:
    config = _cfg(ca)
    role = str(config.get("ca_type") or config.get("role") or "unknown").lower()
    if role in {"root", "root_ca", "root ca"}:
        return "root"
    if role in {"issuing", "subordinate", "sub", "sub_ca", "issuing ca"}:
        return "issuing"
    cert = ca_certificate(config)
    if cert.get("subject") and cert.get("subject") == cert.get("issuer"):
        return "root"
    return "unknown"


def key_protection(config: dict[str, Any]) -> dict[str, Any]:
    raw = config.get("key_protection") if isinstance(config.get("key_protection"), dict) else {}
    provider = str(raw.get("provider") or config.get("crypto_provider") or config.get("provider") or "").strip()
    storage = str(raw.get("storage") or config.get("key_storage") or "").lower().strip()
    hsm_detected = raw.get("hsm_detected")
    provider_l = provider.lower()
    if hsm_detected is True or storage == "hsm" or any(hint in provider_l for hint in HSM_HINTS):
        status = "HSM Protected"
        storage = "hsm"
    elif hsm_detected is False or storage == "software" or any(hint in provider_l for hint in SOFTWARE_HINTS):
        status = "Software Key"
        storage = "software"
    else:
        status = "Unknown"
        storage = storage or "unknown"
    return {
        "status": status,
        "provider": provider or raw.get("provider") or "Not collected",
        "storage": storage,
        "hsm_detected": hsm_detected if hsm_detected is not None else "unknown",
        "evidence": raw.get("evidence") or config.get("key_protection_evidence") or "Not collected",
    }


def _section_status(config: dict[str, Any], name: str) -> str:
    section = config.get(name) if isinstance(config.get(name), dict) else {}
    configured = section.get("configured")
    reachable = section.get("reachable")
    status = section.get("status")
    if status:
        return str(status).replace("_", " ").title()
    if configured is True and reachable is True:
        return "Healthy"
    if configured is True and reachable is None:
        return "Present / Not Tested"
    if configured is True and reachable is False:
        return "Warning"
    if configured is False:
        return "Not Configured"
    return "Not Assessed"


def _risk_badge(role: str, key_status: str, crl_status: str) -> str:
    if role == "root" and key_status == "Software Key":
        return "High"
    if crl_status in {"Critical", "Expired"}:
        return "Critical"
    if key_status == "Software Key" or crl_status in {"Warning", "Not Assessed"}:
        return "Warning"
    return "Normal"


def _node(ca: CertificateAuthority, health_by_ca: dict[str, list[dict]], gaps_by_ca: dict[str, list[dict]]) -> dict[str, Any]:
    config = _cfg(ca)
    cert = ca_certificate(config)
    role = ca_role(ca)
    kp = key_protection(config)
    crl = config.get("crl") if isinstance(config.get("crl"), dict) else {}
    aia = config.get("aia") if isinstance(config.get("aia"), dict) else {}
    ocsp = config.get("ocsp") if isinstance(config.get("ocsp"), dict) else {}
    crl_status = _section_status(config, "crl")
    return {
        "id": config.get("ca_id") or f"{ca.name}|{ca.dns_name}|{cert.get('thumbprint') or cert.get('subject') or ''}",
        "name": ca.name,
        "dns_name": ca.dns_name,
        "role": role.title() if role != "unknown" else "Unknown",
        "status": ca.status or "Not Assessed",
        "subject": cert.get("subject") or "Not collected",
        "issuer": cert.get("issuer") or "Not collected",
        "serial_number": cert.get("serial_number") or "Not collected",
        "thumbprint": cert.get("thumbprint") or "Not collected",
        "not_before": cert.get("not_before") or "Not collected",
        "not_after": cert.get("not_after") or "Not collected",
        "signature_algorithm": cert.get("signature_algorithm") or "Not collected",
        "key_size": cert.get("key_size") or "Not collected",
        "chain_complete": cert.get("chain_complete") if cert.get("chain_complete") is not None else "Not collected",
        "crl_status": crl_status,
        "aia_status": _section_status(config, "aia"),
        "ocsp_status": _section_status(config, "ocsp"),
        "key_protection": kp,
        "risk_badge": _risk_badge(role, kp["status"], crl_status),
        "crl_urls": crl.get("urls") or crl.get("http_urls") or [],
        "aia_urls": aia.get("urls") or aia.get("ca_issuer_urls") or [],
        "ocsp_urls": ocsp.get("urls") or aia.get("ocsp_urls") or [],
        "crl_next_update": crl.get("next_update") or "Not collected",
        "published_templates": config.get("published_templates") or [],
        "health_issues": health_by_ca.get(ca.name, []),
        "best_practice_gaps": gaps_by_ca.get(ca.name, []),
        "children": [],
    }


def build_pki_hierarchy(cas: list[CertificateAuthority], health: dict | None = None, best_practices: dict | None = None) -> dict[str, Any]:
    health_by_ca: dict[str, list[dict]] = defaultdict(list)
    for item in (health or {}).get("items", []):
        if item.get("status") in {"Critical", "Warning", "Not Assessed"}:
            health_by_ca[item.get("affected_object", "")].append(item)
    gaps_by_ca: dict[str, list[dict]] = defaultdict(list)
    for item in (best_practices or {}).get("items", []):
        if item.get("status") in {"Fail", "Warning", "Not Assessed"}:
            gaps_by_ca[item.get("affected_object", "")].append(item)

    nodes = [_node(ca, health_by_ca, gaps_by_ca) for ca in cas]
    subject_map = {node["subject"]: node for node in nodes if node["subject"] != "Not collected"}
    child_ids: set[str] = set()
    for node in nodes:
        issuer = node["issuer"]
        parent = subject_map.get(issuer)
        if parent and parent is not node:
            parent["children"].append(node)
            child_ids.add(node["id"])

    roots = [node for node in nodes if node["id"] not in child_ids and node["role"].lower() == "root"]
    orphans = [node for node in nodes if node["id"] not in child_ids and node not in roots]
    hierarchies: list[dict[str, Any]] = []
    for root in roots:
        hierarchies.append({"name": f"PKI #{len(hierarchies) + 1}", "root": root, "external_root": False})
    for orphan in orphans:
        hierarchies.append(
            {
                "name": f"PKI #{len(hierarchies) + 1}",
                "root": {
                    "name": "Unknown Root / External Root",
                    "role": "Unknown",
                    "status": "Not Assessed",
                    "children": [orphan],
                    "risk_badge": "Unknown",
                    "key_protection": {"status": "Unknown"},
                },
                "external_root": True,
            }
        )
    return {"hierarchies": hierarchies, "ca_count": len(nodes), "independent_hierarchies": len(hierarchies)}
