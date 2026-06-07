from sqlalchemy import text
from sqlalchemy.orm import Session


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

    db.commit()
