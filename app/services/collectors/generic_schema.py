SUPPORTED_COLLECTOR_TYPES = {"adcs", "ejbca", "generic", "tls"}
DEFAULT_SCHEMA_VERSION = "1.1"

NORMALIZED_CONTRACT_KEYS = [
    "collector_type",
    "schema_version",
    "source_host",
    "domain_name",
    "cas",
    "templates",
    "issued_certificates",
    "health_coverage",
    "assessment_hints",
]
