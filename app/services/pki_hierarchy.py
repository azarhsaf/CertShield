from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from app.models.entities import CertificateAuthority

HSM_HINTS = (
    "nshield",
    "ncipher",
    "thales",
    "safenet",
    "luna",
    "utimaco",
    "fortanix",
    "azure key vault",
    "keycontrol",
    "aws cloudhsm",
    "google cloud kms",
    "hsm",
)
SOFTWARE_HINTS = (
    "microsoft software key storage provider",
    "microsoft strong cryptographic provider",
    "microsoft enhanced rsa and aes cryptographic provider",
    "microsoft software",
    "software key",
    "microsoft enhanced",
)


def _cfg(ca: CertificateAuthority) -> dict[str, Any]:
    return ca.config_json or {}


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text[: len(fmt)], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def _days_until(value: Any) -> int | None:
    dt = _parse_date(value)
    if not dt:
        return None
    return (dt - datetime.now(timezone.utc)).days


def ca_certificate(config: dict[str, Any]) -> dict[str, Any]:
    cert = config.get("ca_certificate") if isinstance(config.get("ca_certificate"), dict) else {}
    subject = cert.get("subject") or config.get("certificate_subject") or config.get("subject")
    issuer = cert.get("issuer") or config.get("certificate_issuer") or config.get("issuer")
    not_after = cert.get("not_after") or config.get("certificate_expires_at") or config.get("ca_certificate_expires_at")
    collected = cert.get("collected") if "collected" in cert else bool(subject and issuer)
    collection_error = None if collected else (cert.get("error") or config.get("certificate_collection_reason"))
    return {
        **cert,
        "collected": collected,
        "error": collection_error,
        "subject": subject,
        "issuer": issuer,
        "serial_number": cert.get("serial_number") or config.get("serial_number"),
        "thumbprint": cert.get("thumbprint") or config.get("thumbprint"),
        "not_before": cert.get("not_before") or config.get("certificate_not_before"),
        "not_after": not_after,
        "signature_algorithm": cert.get("signature_algorithm") or config.get("signature_algorithm"),
        "public_key_algorithm": cert.get("public_key_algorithm") or config.get("public_key_algorithm"),
        "key_size": cert.get("key_size") or config.get("key_size"),
        "subject_key_identifier": cert.get("subject_key_identifier") or config.get("subject_key_identifier"),
        "authority_key_identifier": cert.get("authority_key_identifier") or config.get("authority_key_identifier"),
        "is_self_signed": cert.get("is_self_signed") if "is_self_signed" in cert else (subject == issuer if subject and issuer else None),
        "ca_role_hint": cert.get("ca_role_hint") or config.get("ca_role_hint") or config.get("ca_type"),
        "chain_complete": cert.get("chain_complete") if "chain_complete" in cert else config.get("chain_complete"),
    }


def _has_cert_identity(cert: dict[str, Any]) -> bool:
    return bool(cert.get("subject") and cert.get("issuer"))


def ca_role(ca: CertificateAuthority) -> str:
    cert = ca_certificate(_cfg(ca))
    hint = str(cert.get("ca_role_hint") or "").lower().replace("_", " ")
    if _has_cert_identity(cert):
        if cert.get("is_self_signed") is True or cert.get("subject") == cert.get("issuer"):
            return "root"
        if cert.get("subject_key_identifier") and cert.get("subject_key_identifier") == cert.get("authority_key_identifier"):
            return "root"
        if hint in {"root", "root ca"}:
            return "root"
        return "issuing"
    return "unknown"


def key_protection(config: dict[str, Any]) -> dict[str, Any]:
    raw = config.get("key_protection") if isinstance(config.get("key_protection"), dict) else {}

    provider = str(
        raw.get("provider")
        or raw.get("key_storage_provider")
        or raw.get("crypto_provider")
        or config.get("crypto_provider")
        or config.get("key_storage_provider")
        or config.get("provider")
        or ""
    ).strip()

    provider_type = raw.get("provider_type") or config.get("provider_type")
    key_container = raw.get("key_container") or config.get("key_container")
    storage = str(raw.get("storage") or config.get("key_storage") or "").lower().strip()
    hsm_detected = raw.get("hsm_detected")

    evidence = raw.get("evidence") or config.get("key_protection_evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    else:
        evidence = list(evidence)

    evidence_text = " ".join(str(item) for item in evidence).lower()
    provider_l = provider.lower()
    reason = None

    if hsm_detected is True or storage == "hsm" or any(
        hint in provider_l for hint in HSM_HINTS
    ):
        status = "HSM Protected"
        storage = "hsm"
        reason = "Hardware or external key provider evidence was collected."

    elif hsm_detected is False or storage == "software" or any(
        hint in provider_l for hint in SOFTWARE_HINTS
    ):
        status = "Software Key"
        storage = "software"
        reason = "Microsoft software cryptographic provider evidence was collected."

    elif provider:
        status = "Unknown Provider"
        storage = storage or "unknown"
        reason = f"Provider was collected but is not mapped: {provider}"

    elif (
        "0x80070035" in evidence_text
        or "error_bad_netpath" in evidence_text
        or "network path was not found" in evidence_text
    ):
        status = "Collection Failed"
        storage = "unknown"
        reason = "CA host or remote registry path was unreachable (0x80070035)."

    elif "access is denied" in evidence_text or "0x80070005" in evidence_text:
        status = "Collection Failed"
        storage = "unknown"
        reason = "Collector account was denied access to CA key-provider registry evidence."

    elif any("failed" in str(item).lower() for item in evidence):
        status = "Collection Failed"
        storage = "unknown"
        reason = "Key-provider collection failed. Review the collected command evidence."

    else:
        status = "Not Assessed"
        storage = storage or "unknown"
        reason = "No key-provider evidence was returned by the collector."

    return {
        "status": status,
        "provider": provider or "Not collected",
        "provider_type": provider_type or "Not collected",
        "key_container": key_container or "Not collected",
        "storage": storage,
        "hsm_detected": hsm_detected if hsm_detected is not None else "unknown",
        "reason": reason,
        "evidence": evidence or ["No key-provider evidence collected"],
    }



def _section_status(config: dict[str, Any], name: str) -> str:
    section = config.get(name) if isinstance(config.get(name), dict) else {}
    configured = section.get("configured")
    reachable = section.get("reachable")
    status = str(section.get("status") or "").lower()
    if status in {"reachable", "healthy"}:
        return "Healthy"
    if status in {"unreachable", "failed", "critical"}:
        return "Critical"
    if status == "not_configured" or configured is False:
        return "Not Configured"
    if configured is True and reachable is True:
        return "Healthy"
    if configured is True and reachable is None:
        return "Present / Not Tested"
    if configured is True and reachable is False:
        return "Warning"
    return "Not Assessed"


def _risk_badge(
    role: str,
    key_status: str,
    crl_status: str,
    cert_collected: bool,
) -> str:
    if not cert_collected:
        return "Not Assessed"

    if key_status in {"Not Assessed", "Collection Failed"}:
        return "Not Assessed"

    if role == "root" and key_status == "Software Key":
        return "High"

    if crl_status in {"Critical", "Expired"}:
        return "Critical"

    if key_status in {"Software Key", "Unknown Provider"}:
        return "Warning"

    if crl_status in {"Warning", "Not Assessed"}:
        return "Warning"

    return "Normal"



def _node(ca: CertificateAuthority, health_by_ca: dict[str, list[dict]], gaps_by_ca: dict[str, list[dict]]) -> dict[str, Any]:
    config = _cfg(ca)
    cert = ca_certificate(config)
    cert_collected = _has_cert_identity(cert)
    role = ca_role(ca)
    kp = key_protection(config)
    crl = config.get("crl") if isinstance(config.get("crl"), dict) else {}
    aia = config.get("aia") if isinstance(config.get("aia"), dict) else {}
    ocsp = config.get("ocsp") if isinstance(config.get("ocsp"), dict) else {}
    crl_status = _section_status(config, "crl")
    cert_days = _days_until(cert.get("not_after"))
    cert_warning = None
    if not cert_collected:
        cert_warning = "CA certificate details were not collected. Run the latest ADCS collector with CA certificate evidence enabled."
    elif cert.get("error") and not cert.get("collected"):
        cert_warning = cert.get("error")
    return {
        "id": config.get("ca_id") or f"{ca.name}|{ca.dns_name}|{config.get('config_string', '')}|{cert.get('thumbprint') or cert.get('subject') or ''}",
        "name": ca.name,
        "dns_name": ca.dns_name,
        "config_string": config.get("config_string") or "Not collected",
        "metadata_collected": cert_collected,
        "metadata_warning": cert_warning,
        "role": role.title() if role != "unknown" else "Unclassified CA - Insufficient Certificate Metadata",
        "role_key": role,
        "status": ca.status or "Not Assessed",
        "subject": cert.get("subject") or "Not collected",
        "issuer": cert.get("issuer") or "Not collected",
        "serial_number": cert.get("serial_number") or "Not collected",
        "thumbprint": cert.get("thumbprint") or "Not collected",
        "not_before": cert.get("not_before") or "Not collected",
        "not_after": cert.get("not_after") or "Not collected",
        "days_remaining": cert_days if cert_days is not None else "Not collected",
        "signature_algorithm": cert.get("signature_algorithm") or "Not collected",
        "public_key_algorithm": cert.get("public_key_algorithm") or "Not collected",
        "key_size": cert.get("key_size") or "Not collected",
        "subject_key_identifier": cert.get("subject_key_identifier") or "Not collected",
        "authority_key_identifier": cert.get("authority_key_identifier") or "Not collected",
        "is_self_signed": cert.get("is_self_signed") if cert.get("is_self_signed") is not None else "Not collected",
        "chain_complete": cert.get("chain_complete") if cert.get("chain_complete") is not None else "Not collected",
        "crl_status": crl_status,
        "aia_status": _section_status(config, "aia"),
        "ocsp_status": _section_status(config, "ocsp"),
        "key_protection": kp,
        "risk_badge": _risk_badge(role, kp["status"], crl_status, cert_collected),
        "crl_urls": crl.get("urls") or crl.get("http_urls") or [],
        "crl_http_urls": crl.get("http_urls") or [],
        "crl_ldap_urls": crl.get("ldap_urls") or [],
        "crl_file_urls": crl.get("file_urls") or [],
        "crl_reachable": crl.get("reachable") if crl.get("reachable") is not None else "Not Tested",
        "crl_next_update": crl.get("next_update") or "Not collected",
        "crl_this_update": crl.get("this_update") or "Not collected",
        "aia_urls": aia.get("ca_issuer_urls") or aia.get("urls") or [],
        "aia_reachable": aia.get("reachable") if aia.get("reachable") is not None else "Not Tested",
        "ocsp_urls": ocsp.get("urls") or aia.get("ocsp_urls") or [],
        "published_templates": config.get("published_templates") or [],
        "health_issues": health_by_ca.get(ca.name, []),
        "best_practice_gaps": gaps_by_ca.get(ca.name, []),
        "children": [],
    }


def _external_parent(name: str, child: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"external|{name}|{child['id']}",
        "name": "External / Uncollected Parent CA",
        "dns_name": "Not collected",
        "role": "External Parent",
        "role_key": "external",
        "status": "Not Assessed",
        "metadata_collected": False,
        "metadata_warning": "Parent certificate was not collected; hierarchy is inferred only from the child certificate issuer.",
        "subject": name,
        "issuer": "Parent certificate not collected",
        "serial_number": "Not collected",
        "thumbprint": "Not collected",
        "not_before": "Not collected",
        "not_after": "Not collected",
        "days_remaining": "Not collected",
        "signature_algorithm": "Not collected",
        "public_key_algorithm": "Not collected",
        "key_size": "Not collected",
        "subject_key_identifier": "Not collected",
        "authority_key_identifier": "Not collected",
        "is_self_signed": "Not collected",
        "chain_complete": "Not collected",
        "crl_status": "Not Assessed",
        "aia_status": "Not Assessed",
        "ocsp_status": "Not Assessed",
        "key_protection": {"status": "Unknown", "provider": "Not collected", "storage": "unknown"},
        "risk_badge": "Not Assessed",
        "crl_urls": [],
        "crl_http_urls": [],
        "crl_ldap_urls": [],
        "crl_file_urls": [],
        "crl_reachable": "Not Tested",
        "crl_next_update": "Not collected",
        "crl_this_update": "Not collected",
        "aia_urls": [],
        "aia_reachable": "Not Tested",
        "ocsp_urls": [],
        "published_templates": [],
        "health_issues": [],
        "best_practice_gaps": [],
        "children": [child],
        "external_parent_reason": f"Parent certificate for issuer {name} was not included in this scan.",
    }


def build_pki_hierarchy(cas: list[CertificateAuthority], health: dict | None = None, best_practices: dict | None = None) -> dict[str, Any]:
    health_by_ca: dict[str, list[dict]] = defaultdict(list)
    for item in (health or {}).get("items", []):
        if item.get("status") in {"Critical", "Warning", "Not Assessed", "Not Configured", "Present / Not Tested"}:
            health_by_ca[item.get("affected_object", "")].append(item)
    gaps_by_ca: dict[str, list[dict]] = defaultdict(list)
    for item in (best_practices or {}).get("items", []):
        if item.get("status") in {"Fail", "Warning", "Not Assessed"}:
            gaps_by_ca[item.get("affected_object", "")].append(item)

    all_nodes = [_node(ca, health_by_ca, gaps_by_ca) for ca in cas]
    classified = [node for node in all_nodes if node["metadata_collected"]]
    unclassified = [node for node in all_nodes if not node["metadata_collected"]]
    subject_map = {node["subject"]: node for node in classified if node["subject"] != "Not collected"}
    ski_map = {node["subject_key_identifier"]: node for node in classified if node["subject_key_identifier"] != "Not collected"}
    child_ids: set[str] = set()

    for node in classified:
        parent = None
        if node["issuer"] != node["subject"]:
            parent = subject_map.get(node["issuer"])
            if not parent and node["authority_key_identifier"] != "Not collected":
                parent = ski_map.get(node["authority_key_identifier"])
        if parent and parent is not node:
            parent["children"].append(node)
            child_ids.add(node["id"])

    roots = [node for node in classified if node["id"] not in child_ids and node["role_key"] == "root"]
    orphans = [node for node in classified if node["id"] not in child_ids and node not in roots]
    hierarchies: list[dict[str, Any]] = []
    for root in roots:
        hierarchies.append({"name": f"PKI #{len(hierarchies) + 1}", "root": root, "external_root": False, "health": root["risk_badge"]})
    for orphan in orphans:
        issuer = orphan["issuer"]
        if issuer and issuer != "Not collected" and issuer != orphan["subject"]:
            root = _external_parent(issuer, orphan)
            hierarchies.append({"name": f"PKI #{len(hierarchies) + 1}", "root": root, "external_root": True, "health": orphan["risk_badge"]})
        else:
            unclassified.append(orphan)

    return {
        "hierarchies": hierarchies,
        "unclassified": unclassified,
        "ca_count": len(all_nodes),
        "independent_hierarchies": len(hierarchies),
        "root_count": len(roots),
        "issuing_count": sum(1 for node in classified if node["role_key"] == "issuing"),
        "unclassified_count": len(unclassified),
        "crl_issue_count": sum(1 for node in all_nodes if node["crl_status"] in {"Critical", "Warning", "Not Assessed"}),
        "key_warning_count": sum(1 for node in all_nodes if node["key_protection"]["status"] in {"Software Key", "Unknown Provider", "Not Assessed"}),
        "metadata_missing": bool(unclassified),
        "metadata_warning": "Hierarchy could not be built for one or more CAs because CA certificate Subject/Issuer was not collected.",
    }
