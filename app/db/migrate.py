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



def _ensure_environment_schema(db: Session) -> None:
    db.execute(text(
        "CREATE TABLE IF NOT EXISTS pki_environments ("
        "id INTEGER PRIMARY KEY, "
        "name VARCHAR(255) NOT NULL, "
        "environment_key VARCHAR(255) NOT NULL UNIQUE, "
        "collector_type VARCHAR(50) DEFAULT 'adcs', "
        "domain_name VARCHAR(255) DEFAULT '', "
        "forest_name VARCHAR(255) DEFAULT '', "
        "pki_label VARCHAR(255) DEFAULT '', "
        "description TEXT DEFAULT '', "
        "is_demo BOOLEAN DEFAULT 0, "
        "is_active BOOLEAN DEFAULT 1, "
        "created_at DATETIME, "
        "updated_at DATETIME, "
        "last_scan_id INTEGER, "
        "last_scan_at DATETIME"
        ")"
    ))
    db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_pki_environments_environment_key ON pki_environments(environment_key)"))
    scan_columns = {row[1] for row in db.execute(text("PRAGMA table_info(scans)")).fetchall()}
    scan_alters = {
        "environment_id": "ALTER TABLE scans ADD COLUMN environment_id INTEGER",
        "collector_type": "ALTER TABLE scans ADD COLUMN collector_type VARCHAR(50) DEFAULT 'adcs'",
        "scan_sequence": "ALTER TABLE scans ADD COLUMN scan_sequence INTEGER DEFAULT 1",
        "previous_scan_id": "ALTER TABLE scans ADD COLUMN previous_scan_id INTEGER",
        "is_current_for_environment": "ALTER TABLE scans ADD COLUMN is_current_for_environment BOOLEAN DEFAULT 1",
        "collection_mode": "ALTER TABLE scans ADD COLUMN collection_mode VARCHAR(50) DEFAULT 'full'",
        "source_host": "ALTER TABLE scans ADD COLUMN source_host VARCHAR(255) DEFAULT ''",
        "collector_version": "ALTER TABLE scans ADD COLUMN collector_version VARCHAR(100) DEFAULT 'legacy'",
        "schema_version": "ALTER TABLE scans ADD COLUMN schema_version VARCHAR(50) DEFAULT 'legacy'",
    }
    for col, stmt in scan_alters.items():
        if col not in scan_columns:
            db.execute(text(stmt))
    validation_columns = {row[1] for row in db.execute(text("PRAGMA table_info(validation_runs)")).fetchall()}
    if "environment_id" not in validation_columns:
        db.execute(text("ALTER TABLE validation_runs ADD COLUMN environment_id INTEGER"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_environment_id ON scans(environment_id)"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_environment_created ON scans(environment_id, completed_at)"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_environment_current ON scans(environment_id, is_current_for_environment)"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_validation_runs_environment_id ON validation_runs(environment_id)"))

    existing = db.execute(text("SELECT COUNT(*) FROM pki_environments")).scalar() or 0
    scans = db.execute(text("SELECT id, domain_name, source, completed_at FROM scans WHERE environment_id IS NULL ORDER BY id")).fetchall()
    if scans and existing == 0:
        domain = scans[-1][1] or "migrated"
        key = f"migrated:{str(domain).lower()}"
        is_demo = 1 if "corp" in str(domain).lower() or "sample" in str(domain).lower() or "demo" in str(domain).lower() else 0
        name = "Demo - CORP Lab" if is_demo else "Migrated Environment"
        db.execute(
            text(
                "INSERT INTO pki_environments "
                "(name, environment_key, collector_type, domain_name, forest_name, pki_label, description, "
                "is_demo, is_active, created_at, updated_at) "
                "VALUES (:name, :key, 'adcs', :domain, '', :name, '', :is_demo, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {"name": name, "key": key, "domain": domain, "is_demo": is_demo},
        )
    env_id = db.execute(text("SELECT id FROM pki_environments ORDER BY id LIMIT 1")).scalar()
    if env_id:
        db.execute(text("UPDATE scans SET environment_id = :env WHERE environment_id IS NULL"), {"env": env_id})
        latest = db.execute(text("SELECT id, completed_at FROM scans WHERE environment_id = :env ORDER BY id DESC LIMIT 1"), {"env": env_id}).fetchone()
        if latest:
            db.execute(text("UPDATE scans SET is_current_for_environment = 0 WHERE environment_id = :env"), {"env": env_id})
            db.execute(text("UPDATE scans SET is_current_for_environment = 1 WHERE id = :scan"), {"scan": latest[0]})
            db.execute(text("UPDATE pki_environments SET last_scan_id = :scan, last_scan_at = :at WHERE id = :env"), {"scan": latest[0], "at": latest[1], "env": env_id})
        db.execute(text("UPDATE validation_runs SET environment_id = (SELECT environment_id FROM scans WHERE scans.id = validation_runs.scan_id) WHERE environment_id IS NULL"))


def _ensure_monitoring_schema(db: Session) -> None:
    db.execute(
        text(
            "CREATE TABLE IF NOT EXISTS monitoring_agents ("
            "id INTEGER PRIMARY KEY, "
            "environment_id INTEGER NOT NULL, "
            "agent_key VARCHAR(128) NOT NULL UNIQUE, "
            "hostname VARCHAR(255) NOT NULL, "
            "ca_name VARCHAR(255) DEFAULT '', "
            "version VARCHAR(50) DEFAULT '1.0.0', "
            "status VARCHAR(30) DEFAULT 'registered', "
            "is_active BOOLEAN DEFAULT 1, "
            "last_seen_at DATETIME, "
            "audit_success_enabled BOOLEAN DEFAULT 0, "
            "audit_failure_enabled BOOLEAN DEFAULT 0, "
            "audit_filter INTEGER, "
            "audit_ready BOOLEAN DEFAULT 0, "
            "capabilities_json JSON DEFAULT '[]', "
            "metadata_json JSON DEFAULT '{}', "
            "created_at DATETIME, "
            "updated_at DATETIME, "
            "FOREIGN KEY(environment_id) "
            "REFERENCES pki_environments(id)"
            ")"
        )
    )

    db.execute(
        text(
            "CREATE TABLE IF NOT EXISTS monitoring_events ("
            "id INTEGER PRIMARY KEY, "
            "environment_id INTEGER NOT NULL, "
            "agent_id INTEGER NOT NULL, "
            "event_key VARCHAR(255) NOT NULL UNIQUE, "
            "category VARCHAR(50) NOT NULL, "
            "event_type VARCHAR(100) NOT NULL, "
            "severity VARCHAR(30) DEFAULT 'info', "
            "title VARCHAR(255) NOT NULL, "
            "summary TEXT DEFAULT '', "
            "actor VARCHAR(255) DEFAULT '', "
            "source_ip VARCHAR(100) DEFAULT '', "
            "occurred_at DATETIME NOT NULL, "
            "details_json JSON DEFAULT '{}', "
            "created_at DATETIME, "
            "FOREIGN KEY(environment_id) "
            "REFERENCES pki_environments(id), "
            "FOREIGN KEY(agent_id) "
            "REFERENCES monitoring_agents(id)"
            ")"
        )
    )

    db.execute(
        text(
            "CREATE TABLE IF NOT EXISTS monitoring_metrics ("
            "id INTEGER PRIMARY KEY, "
            "environment_id INTEGER NOT NULL, "
            "agent_id INTEGER NOT NULL, "
            "occurred_at DATETIME NOT NULL, "
            "cpu_percent FLOAT, "
            "memory_percent FLOAT, "
            "disk_free_percent FLOAT, "
            "certsvc_state VARCHAR(50) DEFAULT '', "
            "iis_state VARCHAR(50) DEFAULT '', "
            "details_json JSON DEFAULT '{}', "
            "FOREIGN KEY(environment_id) "
            "REFERENCES pki_environments(id), "
            "FOREIGN KEY(agent_id) "
            "REFERENCES monitoring_agents(id)"
            ")"
        )
    )

    db.execute(
        text(
            "CREATE TABLE IF NOT EXISTS monitoring_commands ("
            "id INTEGER PRIMARY KEY, "
            "environment_id INTEGER NOT NULL, "
            "agent_id INTEGER NOT NULL, "
            "command_type VARCHAR(100) NOT NULL, "
            "status VARCHAR(30) DEFAULT 'queued', "
            "requested_by VARCHAR(100) NOT NULL, "
            "requested_at DATETIME, "
            "claimed_at DATETIME, "
            "completed_at DATETIME, "
            "result_json JSON DEFAULT '{}', "
            "FOREIGN KEY(environment_id) "
            "REFERENCES pki_environments(id), "
            "FOREIGN KEY(agent_id) "
            "REFERENCES monitoring_agents(id)"
            ")"
        )
    )

    statements = (
        "CREATE INDEX IF NOT EXISTS "
        "ix_monitoring_agents_environment_id "
        "ON monitoring_agents(environment_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "ix_monitoring_agents_agent_key "
        "ON monitoring_agents(agent_key)",
        "CREATE INDEX IF NOT EXISTS "
        "ix_monitoring_agents_last_seen "
        "ON monitoring_agents(last_seen_at)",
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "ix_monitoring_events_event_key "
        "ON monitoring_events(event_key)",
        "CREATE INDEX IF NOT EXISTS "
        "ix_monitoring_events_environment_time "
        "ON monitoring_events(environment_id, occurred_at)",
        "CREATE INDEX IF NOT EXISTS "
        "ix_monitoring_metrics_environment_time "
        "ON monitoring_metrics(environment_id, occurred_at)",
        "CREATE INDEX IF NOT EXISTS "
        "ix_monitoring_commands_agent_status "
        "ON monitoring_commands(agent_id, status)",
    )

    for statement in statements:
        db.execute(text(statement))


def run_ddl_migrations(db: Session) -> None:
    # Lightweight additive migrations for SQLite and compatibility upgrades.
    _create_validation_tables(db)
    _ensure_environment_schema(db)
    _ensure_monitoring_schema(db)
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

    db.commit()
