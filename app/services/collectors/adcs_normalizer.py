from app.schemas.collector import CollectorPayload


def normalize_adcs_payload(payload: CollectorPayload) -> CollectorPayload:
    """ADCS payloads already arrive in the normalized CertShield schema."""
    return payload
