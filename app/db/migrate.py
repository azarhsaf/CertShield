from sqlalchemy import text
from sqlalchemy.orm import Session


def _table_exists(db: Session, table_name: str) -> bool:
    row = db.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name=:name"), {"name": table_name}).first()
    return row is not None


def _columns(db: Session, table_name: str) -> set[str]:
    if not _table_exists(db, table_name):
        return set()
    return {row[1] for row in db.execute(text(f"PRAGMA table_info({table_name})")).fetchall()}


def run_ddl_migrations(db: Session) -> None:
    # Lightweight additive migrations for SQLite and compatibility upgrades.
    columns = _columns(db, "scans")
    if "coverage_json" not in columns:
        db.execute(text("ALTER TABLE scans ADD COLUMN coverage_json JSON DEFAULT '{}'"))

    finding_columns = _columns(db, "findings")
    finding_alters = {
        "esc_category": "ALTER TABLE findings ADD COLUMN esc_category VARCHAR(50) DEFAULT 'General'",
        "confidence": "ALTER TABLE findings ADD COLUMN confidence VARCHAR(20) DEFAULT 'medium'",
        "coverage_state": "ALTER TABLE findings ADD COLUMN coverage_state VARCHAR(30) DEFAULT 'detected'",
        "risk_score": "ALTER TABLE findings ADD COLUMN risk_score INTEGER DEFAULT 0",
        "exploitability": "ALTER TABLE findings ADD COLUMN exploitability VARCHAR(50) DEFAULT 'unknown'",
        "exposure": "ALTER TABLE findings ADD COLUMN exposure VARCHAR(50) DEFAULT 'unknown'",
        "trigger_conditions": "ALTER TABLE findings ADD COLUMN trigger_conditions TEXT DEFAULT ''",
        "business_impact": "ALTER TABLE findings ADD COLUMN business_impact TEXT DEFAULT ''",
        "technical_impact": "ALTER TABLE findings ADD COLUMN technical_impact TEXT DEFAULT ''",
        "remediation_steps_json": "ALTER TABLE findings ADD COLUMN remediation_steps_json JSON DEFAULT '[]'",
        "score_breakdown_json": "ALTER TABLE findings ADD COLUMN score_breakdown_json JSON DEFAULT '[]'",
        "simulation_summary": "ALTER TABLE findings ADD COLUMN simulation_summary TEXT DEFAULT ''",
        "simulation_json": "ALTER TABLE findings ADD COLUMN simulation_json JSON DEFAULT '{}'",
    }
    for col, stmt in finding_alters.items():
        if col not in finding_columns:
            db.execute(text(stmt))

    db.commit()
