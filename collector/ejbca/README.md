# Future EJBCA Collector

This placeholder documents the intended EJBCA collector direction. It is not an
implemented collector yet.

Expected read-only sources:

- EJBCA REST API for CA list and CA certificate chain.
- Crypto Token / HSM information where the API exposes it.
- Certificate profiles and end entity profiles.
- CA CRL URLs, AIA URLs, and OCSP service information.
- Issued certificate counts, failed/pending request counts, and expiring
  certificate inventory where available.

The EJBCA collector should emit CertShield `schema_version=1.1` normalized PKI
inventory with `collector_type=ejbca`.
