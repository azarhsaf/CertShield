from sqlalchemy import text
from sqlalchemy.orm import Session


def _create_validation_tables(db: Session) -> None:
    db.execute(
        text(
            "CREATE TABLE IF NOT EXISTS validation_runs ("
            "id INTEGER PRIMARY KEY, "
            "finding_id INTEGER NOT NULL, "
            "scan_id INTEGER NOT NULL, "
            "mode VARCHAR(50) DEFAULT 'evidence_replay', "
            "recipe_id VARCHAR(100) NOT NULL, "
            "recipe_version VARCHAR(20) DEFAULT '1.0', "
            "recipe_hash VARCHAR(128) NOT NULL, "
            "target VARCHAR(255) DEFAULT '', "
            "status VARCHAR(30) DEFAULT 'queued', "
            "result VARCHAR(50) DEFAULT 'evidence_incomplete', "
            "confidence VARCHAR(20) DEFAULT 'low', "
            "summary TEXT DEFAULT '', "
            "requested_by VARCHAR(100) DEFAULT 'unknown', "
            "created_at DATETIME, "
            "started_at DATETIME, "
            "completed_at DATETIME, "
            "correlation_id VARCHAR(64) NOT NULL UNIQUE, "
            "safety_json JSON DEFAULT '{}', "
            "evidence_json JSON DEFAULT '{}', "
            "FOREIGN KEY(finding_id) REFERENCES findings(id), "
            "FOREIGN KEY(scan_id) REFERENCES scans(id)"
            ")"
        )
    )

    db.execute(
        text(
            "CREATE TABLE IF NOT EXISTS validation_steps ("
            "id INTEGER PRIMARY KEY, "
            "validation_run_id INTEGER NOT NULL, "
            "sequence INTEGER NOT NULL, "
            "step_name VARCHAR(255) NOT NULL, "
            "status VARCHAR(30) DEFAULT 'info', "
            "message TEXT DEFAULT '', "
            "started_at DATETIME, "
            "completed_at DATETIME, "
            "evidence_json JSON DEFAULT '{}', "
            "FOREIGN KEY(validation_run_id) "
            "REFERENCES validation_runs(id)"
            ")"
        )
    )

    statements = (
        "CREATE INDEX IF NOT EXISTS "
        "ix_validation_runs_finding_id "
        "ON validation_runs(finding_id)",
        "CREATE INDEX IF NOT EXISTS "
        "ix_validation_runs_scan_id "
        "ON validation_runs(scan_id)",
        "CREATE INDEX IF NOT EXISTS "
        "ix_validation_runs_created_at "
        "ON validation_runs(created_at)",
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "ix_validation_runs_correlation_id "
        "ON validation_runs(correlation_id)",
        "CREATE INDEX IF NOT EXISTS "
        "ix_validation_steps_validation_run_id "
        "ON validation_steps(validation_run_id)",
    )

    for statement in statements:
        db.execute(text(statement))


def run_ddl_migrations(db: Session) -> None:
    # Lightweight additive migrations for SQLite and compatibility upgrades.
    columns = {row[1] for row in db.execute(text("PRAGMA table_info(scans)")).fetchall()}
    if "coverage_json" not in columns:
        db.execute(text("ALTER TABLE scans ADD COLUMN coverage_json JSON DEFAULT '{}'"))

    finding_columns = {row[1] for row in db.execute(text("PRAGMA table_info(findings)")).fetchall()}
    alters = {
        "esc_category": "ALTER TABLE findings ADD COLUMN esc_category VARCHAR(50) DEFAULT 'General'",
        "confidence": "ALTER TABLE findings ADD COLUMN confidence VARCHAR(20) DEFAULT 'medium'",
        "coverage_state": "ALTER TABLE findings ADD COLUMN coverage_state VARCHAR(30) DEFAULT 'detected'",
        "trigger_conditions": "ALTER TABLE findings ADD COLUMN trigger_conditions TEXT DEFAULT ''",
        "remediation_steps_json": "ALTER TABLE findings ADD COLUMN remediation_steps_json JSON DEFAULT '[]'",
        "simulation_summary": "ALTER TABLE findings ADD COLUMN simulation_summary TEXT DEFAULT ''",
        "simulation_json": "ALTER TABLE findings ADD COLUMN simulation_json JSON DEFAULT '{}'",
    }
    for col, stmt in alters.items():
        if col not in finding_columns:
            db.execute(text(stmt))

    db.execute(text(
        "CREATE TABLE IF NOT EXISTS risk_acceptances ("
        "id INTEGER PRIMARY KEY, "
        "finding_id INTEGER, "
        "fingerprint VARCHAR(128) NOT NULL, "
        "object_type VARCHAR(50) NOT NULL, "
        "object_name VARCHAR(255) NOT NULL, "
        "category VARCHAR(100) NOT NULL, "
        "risk_title VARCHAR(255) NOT NULL, "
        "severity VARCHAR(20) DEFAULT 'Medium', "
        "accepted_by VARCHAR(100) NOT NULL, "
        "accepted_at DATETIME, "
        "expiry_date VARCHAR(50) DEFAULT '', "
        "business_justification TEXT DEFAULT '', "
        "compensating_control TEXT DEFAULT '', "
        "status VARCHAR(30) DEFAULT 'active', "
        "scope VARCHAR(50) DEFAULT 'exact_fingerprint', "
        "created_at DATETIME"
        ")"
    ))
    acceptance_columns = {row[1] for row in db.execute(text("PRAGMA table_info(risk_acceptances)")).fetchall()}
    if "severity" not in acceptance_columns:
        db.execute(text("ALTER TABLE risk_acceptances ADD COLUMN severity VARCHAR(20) DEFAULT 'Medium'"))

    _create_validation_tables(db)

    db.commit()
